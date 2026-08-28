package gnb

// NR-DC Xn handover support (phase 1 plumbing).
//
// Xn frames gain a leading type byte (see XnPdu). Type 0 is the existing
// raw-NGAP relay used by the DC establishment flow; types 1/2 carry the
// handover context transfer as JSON. The target gNB, on receiving a
// handover request, allocates its own RAN UE NGAP ID and DL TEID, sends a
// PathSwitchRequest (with the NR-DC AdditionalDLQosFlowPerTNLInformation
// extension) to the AMF on its own N2 association, waits for the
// Acknowledge, and answers the source over the same Xn connection.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/free-ran-ue/free-ran-ue/v2/constant"
	"github.com/free-ran-ue/util"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
	"github.com/gin-gonic/gin"
)

const (
	XnTypeNgap             byte = 0
	XnTypeHandoverRequest  byte = 1
	XnTypeHandoverAck      byte = 2
	XnTypeHandoverComplete byte = 3
)

// XnHandoverContext is the UE context the source gNB transfers to the
// handover target. TEIDs travel as hex strings.
type XnHandoverContext struct {
	Imsi              string `json:"imsi"`
	AmfUeNgapId       int64  `json:"amfUeNgapId"`
	SourceRanUeNgapId int64  `json:"sourceRanUeNgapId"`
	UlTeid            string `json:"ulTeid"`    // UPF UL TEID (primary leg)
	SecondaryDlTeid   string `json:"secDlTeid"` // DL TEID of the leg that stays/becomes secondary
	SecondaryN3Ip     string `json:"secN3Ip"`   // N3 address of that secondary leg
	PduSessionId      int64  `json:"pduSessionId"`
}

// XnHandoverAckMsg is the target's answer: where the UE should re-anchor.
type XnHandoverAckMsg struct {
	Accepted      bool   `json:"accepted"`
	Reason        string `json:"reason,omitempty"`
	TargetCpIp    string `json:"targetCpIp"`
	TargetCpPort  int    `json:"targetCpPort"`
	TargetDpIp    string `json:"targetDpIp"`
	TargetDpPort  int    `json:"targetDpPort"`
	UlPrimaryTeid string `json:"ulPrimaryTeid"` // from PathSwitchRequestAcknowledge
	UlDcTeid      string `json:"ulDcTeid"`
	// Deferred marks the two-phase (MN->MN') flow: the target has prepared
	// the handover but will only send the PathSwitchRequest after the UE
	// re-anchors. The source must push UE_HANDOVER_COMMAND and then wait
	// for an XnTypeHandoverComplete frame on the same Xn connection.
	Deferred bool `json:"deferred,omitempty"`
}

// ueHandoverTarget is the payload of UE_HANDOVER_COMMAND pushed to the UE
// over N1: where to re-anchor its control and data planes.
type ueHandoverTarget struct {
	CpIp   string `json:"cpIp"`
	CpPort int    `json:"cpPort"`
	DpIp   string `json:"dpIp"`
	DpPort int    `json:"dpPort"`
}

// pendingHandoverEntry is stored on the target between the Xn handover
// request and the UE's control-plane re-attach.
type pendingHandoverEntry struct {
	ctx          XnHandoverContext
	xnConn       net.Conn // held open for the XnTypeHandoverComplete reply (deferred flow)
	targetDlTeid []byte
	ranUeNgapId  int64
}

type pathSwitchAckResult struct {
	ulPrimaryTeid []byte
	ulDcTeid      []byte
	err           error
}

// buildPathSwitchRequestWithDC builds the NGAP PathSwitchRequest for this
// gNB as the new master: primary DL tunnel = (g.ranN3Ip, newDlTeid), and
// the NR-DC extension carrying the secondary DL tunnel unchanged.
func (g *Gnb) buildPathSwitchRequestWithDC(
	includeDcExt bool,
	ranUeNgapId, amfUeNgapId, pduSessionId int64,
	newDlTeid []byte, secondaryDlTeid []byte, secondaryN3Ip string,
) ([]byte, error) {
	transfer := ie.PathSwitchRequestTransfer{
		DLNGUUPTNLInformation: &ie.UPTransportLayerInformation{
			Choice: &ie.GTPTunnel{
				GTPTEID: &ie.GTPTEID{Value: newDlTeid},
				TransportLayerAddress: &ie.TransportLayerAddress{
					Value: ngapConvertIPAddressToNgap(g.ranN3Ip),
				},
			},
		},
		QosFlowAcceptedList: &ie.QosFlowAcceptedList{
			List: []ie.QosFlowAcceptedItem{
				{QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1}},
			},
		},
	}
	// The DC extension is deliberately optional. When absent, the SMF
	// (merge/nrdc HandlePathSwitchRequestTransfer) leaves DCTunnel and the
	// secondary-leg FARs byte-identical - which is exactly the semantics of
	// an MN->MN' handover with the SN unchanged, and it sidesteps the
	// unconditional SendEndMarker on the secondary leg.
	if includeDcExt {
		transfer.IEExtensions = &ie.ProtocolExtensionContainerPathSwitchRequestTransferExtIEs{
			List: []ie.PathSwitchRequestTransferExtIEs{
				{
					Id:          &ie.ProtocolExtensionID{Value: 155},
					Criticality: &ie.Criticality{Value: ie.CriticalityPresentIgnore},
					AdditionalDLQosFlowPerTNLInformation: &ie.QosFlowPerTNLInformationList{
						List: []ie.QosFlowPerTNLInformationItem{
							buildDCQosFlowPerTNLInformationItem(secondaryDlTeid, secondaryN3Ip),
						},
					},
				},
			},
		}
	}
	transferBytes, err := ie.MarshalBinary(&transfer)
	if err != nil {
		return nil, fmt.Errorf("marshal PathSwitchRequestTransfer: %v", err)
	}
	transferOctet := aper.OctetString(transferBytes)

	full := aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}
	psReq := message.PathSwitchRequest{
		RANUENGAPID:             &ie.RANUENGAPID{Value: ranUeNgapId},
		SourceAMFUENGAPID:       &ie.AMFUENGAPID{Value: amfUeNgapId},
		UserLocationInformation: buildUserLocationInformationNR(g.plmnId, g.tai, g.gnbId),
		UESecurityCapabilities: &ie.UESecurityCapabilities{
			NRencryptionAlgorithms:             &ie.NRencryptionAlgorithms{Value: full},
			NRintegrityProtectionAlgorithms:    &ie.NRintegrityProtectionAlgorithms{Value: full},
			EUTRAencryptionAlgorithms:          &ie.EUTRAencryptionAlgorithms{Value: full},
			EUTRAintegrityProtectionAlgorithms: &ie.EUTRAintegrityProtectionAlgorithms{Value: full},
		},
		PDUSessionResourceToBeSwitchedDLList: &ie.PDUSessionResourceToBeSwitchedDLList{
			List: []ie.PDUSessionResourceToBeSwitchedDLItem{
				{
					PDUSessionID:              &ie.PDUSessionID{Value: pduSessionId},
					PathSwitchRequestTransfer: &transferOctet,
				},
			},
		},
	}
	return psReq.MarshalBinary()
}

// pathSwitchRequestAcknowledgeProcessor runs on the NGAP dispatcher when
// the AMF acknowledges our PathSwitchRequest. It extracts both UL tunnels
// and hands them to the waiting handover processor.
func (d *ngapDispatcher) pathSwitchRequestAcknowledgeProcessor(g *Gnb, msg *message.PathSwitchRequestAcknowledge) {
	res := pathSwitchAckResult{}

	if msg.PDUSessionResourceSwitchedList == nil || len(msg.PDUSessionResourceSwitchedList.List) == 0 {
		res.err = fmt.Errorf("PathSwitchRequestAcknowledge without switched list")
		g.deliverPathSwitchAck(msg.RANUENGAPID, res)
		return
	}
	item := msg.PDUSessionResourceSwitchedList.List[0]
	if item.PathSwitchRequestAcknowledgeTransfer == nil {
		res.err = fmt.Errorf("switched item without acknowledge transfer")
		g.deliverPathSwitchAck(msg.RANUENGAPID, res)
		return
	}

	var ackTransfer ie.PathSwitchRequestAcknowledgeTransfer
	if err := ie.UnmarshalBinary(*item.PathSwitchRequestAcknowledgeTransfer, &ackTransfer); err != nil {
		res.err = fmt.Errorf("unmarshal acknowledge transfer: %v", err)
		g.deliverPathSwitchAck(msg.RANUENGAPID, res)
		return
	}

	if ackTransfer.ULNGUUPTNLInformation != nil {
		if gtp, ok := ackTransfer.ULNGUUPTNLInformation.Choice.(*ie.GTPTunnel); ok && gtp.GTPTEID != nil {
			res.ulPrimaryTeid = gtp.GTPTEID.Value
		}
	}
	if ackTransfer.IEExtensions != nil {
		for _, ext := range ackTransfer.IEExtensions.List {
			if ext.AdditionalNGUUPTNLInformation != nil && len(ext.AdditionalNGUUPTNLInformation.List) > 0 {
				pair := ext.AdditionalNGUUPTNLInformation.List[0]
				if pair.ULNGUUPTNLInformation != nil {
					if gtp, ok := pair.ULNGUUPTNLInformation.Choice.(*ie.GTPTunnel); ok && gtp.GTPTEID != nil {
						res.ulDcTeid = gtp.GTPTEID.Value
					}
				}
			}
		}
	}
	if res.ulPrimaryTeid == nil {
		res.err = fmt.Errorf("acknowledge transfer without UL tunnel")
	}
	g.NgapLog.Infof("Path Switch acknowledged: UL primary TEID %s, UL DC TEID %s",
		hex.EncodeToString(res.ulPrimaryTeid), hex.EncodeToString(res.ulDcTeid))
	g.deliverPathSwitchAck(msg.RANUENGAPID, res)
}

func (g *Gnb) deliverPathSwitchAck(ranUeNgapId *ie.RANUENGAPID, res pathSwitchAckResult) {
	if ranUeNgapId == nil {
		g.NgapLog.Warnln("PathSwitchRequestAcknowledge without RANUENGAPID")
		return
	}
	if ch, ok := g.pathSwitchAckChans.Load(ranUeNgapId.Value); ok {
		ch.(chan pathSwitchAckResult) <- res
	} else {
		g.NgapLog.Warnf("No waiter for PathSwitch ack (ranUeNgapId %d)", ranUeNgapId.Value)
	}
}

// xnHandoverRequestProcessor runs on the HANDOVER TARGET when the source
// gNB transfers the UE context over Xn. It performs the path switch toward
// the AMF and answers the source with the re-anchor endpoints.
func xnHandoverRequestProcessor(g *Gnb, conn net.Conn, xnPdu *XnPdu) {
	g.XnLog.Infoln("Processing XN Handover Request")

	var hoCtx XnHandoverContext
	if err := json.Unmarshal(xnPdu.Data, &hoCtx); err != nil {
		g.XnLog.Errorf("Error unmarshal handover context: %v", err)
		xnHandoverReply(g, conn, hoCtx.Imsi, XnHandoverAckMsg{Accepted: false, Reason: err.Error()})
		return
	}
	g.XnLog.Tracef("Handover context: %+v", hoCtx)

	secondaryDlTeid, err := hex.DecodeString(hoCtx.SecondaryDlTeid)
	if err != nil {
		g.XnLog.Errorf("Error decode secondary DL TEID: %v", err)
		xnHandoverReply(g, conn, hoCtx.Imsi, XnHandoverAckMsg{Accepted: false, Reason: err.Error()})
		return
	}

	ranUeNgapId := g.ranUeNgapIdGenerator.AllocateRanUeId()

	// Role swap (MN->SN): if this gNB already serves the UE's secondary leg,
	// reuse that leg's DL TEID as the new primary. DL forwarding to the UE
	// then works the instant the UPF's FAR rewrite lands - no UE re-anchor
	// needed for the data plane. A fresh TEID is only allocated when this
	// gNB has no existing leg for the UE (the MN->MN' case).
	var targetDlTeid []byte
	g.xnUeConns.Range(func(key, value any) bool {
		if xnUe, ok := key.(*XnUe); ok && xnUe.GetIMSI() == hoCtx.Imsi {
			targetDlTeid = xnUe.GetDlTeid()
			return false
		}
		return true
	})
	reusedLeg := targetDlTeid != nil
	if !reusedLeg {
		targetDlTeid = g.teidGenerator.AllocateTeid()
	}
	g.XnLog.Infof("Handover target DL TEID %s (reused existing leg: %v)",
		hex.EncodeToString(targetDlTeid), reusedLeg)

	if !reusedLeg {
		// MN->MN' (no existing leg here): two-phase. The UE's data-plane
		// socket is connected to the old master, so DL delivered here would
		// be undeliverable until the UE re-anchors. Prepare, ack with our
		// endpoints, and only send the PathSwitchRequest once the UE has
		// attached (completePendingHandover). Make-before-break.
		g.ranUeNgapIdGenerator.ReleaseRanUeId(ranUeNgapId) // attach conn brings its own
		g.pendingHandover.Store(hoCtx.Imsi, &pendingHandoverEntry{
			ctx:          hoCtx,
			xnConn:       conn,
			targetDlTeid: targetDlTeid,
			ranUeNgapId:  -1,
		})
		xnHandoverReply(g, conn, hoCtx.Imsi, XnHandoverAckMsg{
			Accepted:     true,
			Deferred:     true,
			TargetCpIp:   g.ranControlPlaneIp,
			TargetCpPort: g.ranControlPlanePort,
			TargetDpIp:   g.ranDataPlaneIp,
			TargetDpPort: g.ranDataPlanePort,
		})
		g.XnLog.Infoln("XN Handover Request prepared (deferred: awaiting UE re-anchor)")
		return
	}

	ackChan := make(chan pathSwitchAckResult, 1)
	g.pathSwitchAckChans.Store(ranUeNgapId, ackChan)
	defer g.pathSwitchAckChans.Delete(ranUeNgapId)

	psRaw, err := g.buildPathSwitchRequestWithDC(
		true,
		ranUeNgapId, hoCtx.AmfUeNgapId, hoCtx.PduSessionId,
		targetDlTeid, secondaryDlTeid, hoCtx.SecondaryN3Ip)
	if err != nil {
		g.XnLog.Errorf("Error build PathSwitchRequest: %v", err)
		xnHandoverReply(g, conn, hoCtx.Imsi, XnHandoverAckMsg{Accepted: false, Reason: err.Error()})
		return
	}

	if _, err := g.n2Conn.Write(psRaw); err != nil {
		g.XnLog.Errorf("Error send PathSwitchRequest to AMF: %v", err)
		xnHandoverReply(g, conn, hoCtx.Imsi, XnHandoverAckMsg{Accepted: false, Reason: err.Error()})
		return
	}
	g.NgapLog.Infoln("Sent PathSwitchRequest (NR-DC) to AMF")

	var ack pathSwitchAckResult
	select {
	case ack = <-ackChan:
	case <-time.After(5 * time.Second):
		ack.err = fmt.Errorf("timeout waiting for PathSwitchRequestAcknowledge")
	}
	if ack.err != nil {
		g.XnLog.Errorf("Path switch failed: %v", ack.err)
		xnHandoverReply(g, conn, hoCtx.Imsi, XnHandoverAckMsg{Accepted: false, Reason: ack.err.Error()})
		return
	}

	// Keep the context for the UE's control-plane re-attach.
	g.pendingHandover.Store(hoCtx.Imsi, &pendingHandoverEntry{
		ctx:          hoCtx,
		targetDlTeid: targetDlTeid,
		ranUeNgapId:  ranUeNgapId,
	})

	xnHandoverReply(g, conn, hoCtx.Imsi, XnHandoverAckMsg{
		Accepted:      true,
		TargetCpIp:    g.ranControlPlaneIp,
		TargetCpPort:  g.ranControlPlanePort,
		TargetDpIp:    g.ranDataPlaneIp,
		TargetDpPort:  g.ranDataPlanePort,
		UlPrimaryTeid: hex.EncodeToString(ack.ulPrimaryTeid),
		UlDcTeid:      hex.EncodeToString(ack.ulDcTeid),
	})
	g.XnLog.Infoln("XN Handover Request completed (path switched)")
}

func xnHandoverReply(g *Gnb, conn net.Conn, imsi string, ack XnHandoverAckMsg) {
	payload, err := json.Marshal(ack)
	if err != nil {
		g.XnLog.Errorf("Error marshal handover ack: %v", err)
		return
	}
	pdu := NewTypedXnPdu(XnTypeHandoverAck, imsi, payload)
	raw, err := pdu.Marshal()
	if err != nil {
		g.XnLog.Errorf("Error marshal handover ack xn pdu: %v", err)
		return
	}
	if _, err := conn.Write(raw); err != nil {
		g.XnLog.Errorf("Error send handover ack: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Source side: trigger + Xn transfer (MN -> SN role swap)
// ---------------------------------------------------------------------------

type ConsoleGnbUeHandoverRequest struct {
	Imsi         string `json:"imsi" binding:"required"`
	PduSessionId int64  `json:"pduSessionId"`
	TargetXn     string `json:"targetXn,omitempty"`
}

type ConsoleGnbUeHandoverResponse struct {
	Message       string `json:"message"`
	UlPrimaryTeid string `json:"ulPrimaryTeid,omitempty"`
	UlDcTeid      string `json:"ulDcTeid,omitempty"`
}

func (g *Gnb) handleConsoleGnbUeHandover(c *gin.Context) {
	var request ConsoleGnbUeHandoverRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		g.ApiLog.Warnf("Error bind console gnb ue handover request: %v", err)
		c.JSON(http.StatusBadRequest, ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Error bind console gnb ue handover request: %v", err),
		})
		return
	}
	if request.PduSessionId == 0 {
		request.PduSessionId = int64(constant.PDU_SESSION_ID)
	}
	targetXnIp, targetXnPort := "", 0
	if request.TargetXn != "" {
		host, portStr, err := net.SplitHostPort(request.TargetXn)
		if err != nil {
			c.JSON(http.StatusBadRequest, ConsoleGnbUeHandoverResponse{
				Message: fmt.Sprintf("Invalid targetXn %q: %v", request.TargetXn, err),
			})
			return
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ConsoleGnbUeHandoverResponse{
				Message: fmt.Sprintf("Invalid targetXn port %q: %v", portStr, err),
			})
			return
		}
		targetXnIp, targetXnPort = host, port
	}

	var ranUe *RanUe
	g.ranUeConns.Range(func(key, value any) bool {
		if value.(*RanUe).GetMobileIdentityIMSI() == request.Imsi {
			ranUe = value.(*RanUe)
		}
		return true
	})
	if ranUe == nil {
		g.ApiLog.Warnf("UE %s not found", request.Imsi)
		c.JSON(http.StatusNotFound, ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("UE %s not found", request.Imsi),
		})
		return
	}

	ack, err := g.processMnToSnHandover(ranUe, request.PduSessionId, targetXnIp, targetXnPort)
	if err != nil {
		g.ApiLog.Errorf("Error process handover: %v", err)
		c.JSON(http.StatusInternalServerError, ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Error process handover: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, ConsoleGnbUeHandoverResponse{
		Message:       fmt.Sprintf("UE %s handover success", request.Imsi),
		UlPrimaryTeid: ack.UlPrimaryTeid,
		UlDcTeid:      ack.UlDcTeid,
	})
}

// processMnToSnHandover transfers the UE context to the Xn peer (the current
// secondary), which performs the path switch and becomes the new master.
// This gNB keeps serving its leg, now as the secondary.
func (g *Gnb) processMnToSnHandover(ranUe *RanUe, pduSessionId int64, targetXnIp string, targetXnPort int) (*XnHandoverAckMsg, error) {
	if targetXnIp == "" {
		targetXnIp = g.xnInterface.xnDialIp
		targetXnPort = g.xnInterface.xnDialPort
	}
	g.XnLog.Infof("Processing handover for UE %s to Xn target %s:%d",
		ranUe.GetMobileIdentityIMSI(), targetXnIp, targetXnPort)

	hoCtx := XnHandoverContext{
		Imsi:              ranUe.GetMobileIdentityIMSI(),
		AmfUeNgapId:       ranUe.GetAmfUeId(),
		SourceRanUeNgapId: ranUe.GetRanUeId(),
		UlTeid:            hex.EncodeToString(ranUe.GetUlTeid()),
		SecondaryDlTeid:   hex.EncodeToString(ranUe.GetDlTeid()),
		SecondaryN3Ip:     g.ranN3Ip,
		PduSessionId:      pduSessionId,
	}
	payload, err := json.Marshal(hoCtx)
	if err != nil {
		return nil, fmt.Errorf("marshal handover context: %v", err)
	}

	xnConn, err := util.TcpDialWithOptionalLocalAddress(targetXnIp, targetXnPort, "")
	if err != nil {
		return nil, fmt.Errorf("dial xn: %v", err)
	}
	defer func() {
		if err := xnConn.Close(); err != nil {
			g.XnLog.Warnf("Error close xn connection: %v", err)
		}
	}()

	pdu := NewTypedXnPdu(XnTypeHandoverRequest, hoCtx.Imsi, payload)
	raw, err := pdu.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal xn pdu: %v", err)
	}
	if _, err := xnConn.Write(raw); err != nil {
		return nil, fmt.Errorf("send handover request to xn: %v", err)
	}
	g.XnLog.Debugln("Sent XN Handover Request")

	if err := xnConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("set read deadline: %v", err)
	}
	buffer := make([]byte, 4096)
	n, err := xnConn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read handover ack from xn: %v", err)
	}

	ackPdu := &XnPdu{}
	if err := ackPdu.Unmarshal(buffer[:n]); err != nil {
		return nil, fmt.Errorf("unmarshal handover ack xn pdu: %v", err)
	}
	if ackPdu.Type != XnTypeHandoverAck {
		return nil, fmt.Errorf("unexpected xn pdu type %d in handover ack", ackPdu.Type)
	}
	var ack XnHandoverAckMsg
	if err := json.Unmarshal(ackPdu.Data, &ack); err != nil {
		return nil, fmt.Errorf("unmarshal handover ack: %v", err)
	}
	if !ack.Accepted {
		return nil, fmt.Errorf("handover rejected by target: %s", ack.Reason)
	}

	if !ack.Deferred {
		g.XnLog.Infof("Handover complete: this gNB is now the secondary for UE %s "+
			"(UL primary TEID %s, UL DC TEID %s)", hoCtx.Imsi, ack.UlPrimaryTeid, ack.UlDcTeid)
		return &ack, nil
	}

	// Deferred (MN->MN') flow: push the re-anchor command to the UE over N1,
	// then wait on the same Xn connection for the target's completion notice
	// (the target sends its PathSwitchRequest only after the UE attaches).
	targetJson, err := json.Marshal(ueHandoverTarget{
		CpIp:   ack.TargetCpIp,
		CpPort: ack.TargetCpPort,
		DpIp:   ack.TargetDpIp,
		DpPort: ack.TargetDpPort,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal ue handover target: %v", err)
	}
	if _, err := ranUe.GetN1Conn().Write(append([]byte(constant.UE_HANDOVER_COMMAND+" "), targetJson...)); err != nil {
		return nil, fmt.Errorf("send handover command to UE: %v", err)
	}
	g.RanLog.Infof("Sent handover command to UE %s (target %s:%d)", hoCtx.Imsi, ack.TargetCpIp, ack.TargetCpPort)

	if err := xnConn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return nil, fmt.Errorf("set read deadline: %v", err)
	}
	n, err = xnConn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read handover complete from xn: %v", err)
	}
	completePdu := &XnPdu{}
	if err := completePdu.Unmarshal(buffer[:n]); err != nil {
		return nil, fmt.Errorf("unmarshal handover complete xn pdu: %v", err)
	}
	if completePdu.Type != XnTypeHandoverComplete {
		return nil, fmt.Errorf("unexpected xn pdu type %d in handover complete", completePdu.Type)
	}
	var complete XnHandoverAckMsg
	if err := json.Unmarshal(completePdu.Data, &complete); err != nil {
		return nil, fmt.Errorf("unmarshal handover complete: %v", err)
	}
	if !complete.Accepted {
		return nil, fmt.Errorf("handover failed at target: %s", complete.Reason)
	}

	g.XnLog.Infof("Handover complete: UE %s moved to new master (UL primary TEID %s); "+
		"this gNB no longer serves it", hoCtx.Imsi, complete.UlPrimaryTeid)
	return &complete, nil
}

// pathSwitchRequestFailureProcessor delivers the AMF's rejection to the
// waiting handover flow immediately instead of burning the ack timeout.
func (d *ngapDispatcher) pathSwitchRequestFailureProcessor(g *Gnb, msg *message.PathSwitchRequestFailure) {
	if msg.RANUENGAPID == nil {
		g.NgapLog.Warnln("PathSwitchRequestFailure without RAN UE NGAP ID")
		return
	}
	g.deliverPathSwitchAck(msg.RANUENGAPID, pathSwitchAckResult{
		err: fmt.Errorf("PathSwitchRequestFailure from AMF"),
	})
}

// completePendingHandover runs on the target after the UE has re-anchored
// its control plane here (MN->MN' deferred flow): send the PathSwitchRequest
// (no DC extension - the SN leg must stay byte-identical at the SMF), await
// the Ack, then notify the source over the held Xn connection.
func (g *Gnb) completePendingHandover(imsi string, ranUe *RanUe) error {
	entryValue, exists := g.pendingHandover.Load(imsi)
	if !exists {
		return fmt.Errorf("no pending handover for %s", imsi)
	}
	g.pendingHandover.Delete(imsi)
	entry := entryValue.(*pendingHandoverEntry)

	ackChan := make(chan pathSwitchAckResult, 1)
	g.pathSwitchAckChans.Store(ranUe.GetRanUeId(), ackChan)
	defer g.pathSwitchAckChans.Delete(ranUe.GetRanUeId())

	psRaw, err := g.buildPathSwitchRequestWithDC(
		false,
		ranUe.GetRanUeId(), entry.ctx.AmfUeNgapId, entry.ctx.PduSessionId,
		ranUe.GetDlTeid(), nil, "")
	if err != nil {
		g.notifyHandoverComplete(entry, imsi, XnHandoverAckMsg{Accepted: false, Reason: err.Error()})
		return fmt.Errorf("build PathSwitchRequest: %v", err)
	}
	if _, err := g.n2Conn.Write(psRaw); err != nil {
		g.notifyHandoverComplete(entry, imsi, XnHandoverAckMsg{Accepted: false, Reason: err.Error()})
		return fmt.Errorf("send PathSwitchRequest: %v", err)
	}
	g.NgapLog.Infoln("Sent PathSwitchRequest (MN->MN', no DC ext) to AMF")

	var ack pathSwitchAckResult
	select {
	case ack = <-ackChan:
	case <-time.After(5 * time.Second):
		ack.err = fmt.Errorf("timeout waiting for PathSwitchRequestAcknowledge")
	}
	if ack.err != nil {
		g.notifyHandoverComplete(entry, imsi, XnHandoverAckMsg{Accepted: false, Reason: ack.err.Error()})
		return fmt.Errorf("path switch failed: %v", ack.err)
	}

	if len(ack.ulPrimaryTeid) > 0 {
		ranUe.SetUlTeid(ack.ulPrimaryTeid)
	}
	g.notifyHandoverComplete(entry, imsi, XnHandoverAckMsg{
		Accepted:      true,
		UlPrimaryTeid: hex.EncodeToString(ack.ulPrimaryTeid),
		UlDcTeid:      hex.EncodeToString(ack.ulDcTeid),
	})
	g.XnLog.Infof("Handover complete: this gNB is now the master for UE %s (path switched)", imsi)
	return nil
}

func (g *Gnb) notifyHandoverComplete(entry *pendingHandoverEntry, imsi string, msg XnHandoverAckMsg) {
	payload, err := json.Marshal(msg)
	if err != nil {
		g.XnLog.Errorf("Error marshal handover complete: %v", err)
		return
	}
	pdu := NewTypedXnPdu(XnTypeHandoverComplete, imsi, payload)
	raw, err := pdu.Marshal()
	if err != nil {
		g.XnLog.Errorf("Error marshal handover complete xn pdu: %v", err)
		return
	}
	if _, err := entry.xnConn.Write(raw); err != nil {
		g.XnLog.Errorf("Error send handover complete to source: %v", err)
	}
	if err := entry.xnConn.Close(); err != nil {
		g.XnLog.Debugf("Close xn connection after handover complete: %v", err)
	}
}

// processHandoverAttach adopts a UE whose control plane just re-anchored to
// this gNB via UE_HANDOVER_ATTACH (deferred MN->MN' flow). The accept loop
// has already allocated this connection's RanUe and stored it in ranUeConns,
// so NGAP downlink for the new RAN UE NGAP ID routes here automatically.
func (g *Gnb) processHandoverAttach(ranUe *RanUe, imsi string) error {
	g.RanLog.Infof("Processing handover attach for UE %s", imsi)

	entryValue, exists := g.pendingHandover.Load(imsi)
	if !exists {
		return fmt.Errorf("no pending handover for %s", imsi)
	}
	entry := entryValue.(*pendingHandoverEntry)

	ranUe.imsiOverride = imsi
	ranUe.SetAmfUeId(entry.ctx.AmfUeNgapId)
	if ulTeid, err := hex.DecodeString(entry.ctx.UlTeid); err == nil && len(ulTeid) > 0 {
		ranUe.SetUlTeid(ulTeid)
	}
	ranUe.SetDlTeid(entry.targetDlTeid)
	ranUe.ActivateNrdc()

	g.dlTeidToUe.Store(hex.EncodeToString(ranUe.GetDlTeid()), ranUe)
	g.imsiTodlTeidAndUeType.Store(imsi, dlTeidAndUeType{
		dlTeid: ranUe.GetDlTeid(),
		ueType: constant.UE_TYPE_RAN,
	})
	g.RanLog.Infof("Adopted UE %s (RAN UE NGAP ID %d, DL TEID %s)",
		imsi, ranUe.GetRanUeId(), hex.EncodeToString(ranUe.GetDlTeid()))

	return g.completePendingHandover(imsi, ranUe)
}

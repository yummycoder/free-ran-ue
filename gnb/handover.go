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
	"time"

	"github.com/free-ran-ue/util"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
	"github.com/gin-gonic/gin"
)

const (
	XnTypeNgap            byte = 0
	XnTypeHandoverRequest byte = 1
	XnTypeHandoverAck     byte = 2
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
}

// pendingHandoverEntry is stored on the target between the Xn handover
// request and the UE's control-plane re-attach.
type pendingHandoverEntry struct {
	ctx          XnHandoverContext
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
		IEExtensions: &ie.ProtocolExtensionContainerPathSwitchRequestTransferExtIEs{
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
		},
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

	ackChan := make(chan pathSwitchAckResult, 1)
	g.pathSwitchAckChans.Store(ranUeNgapId, ackChan)
	defer g.pathSwitchAckChans.Delete(ranUeNgapId)

	psRaw, err := g.buildPathSwitchRequestWithDC(
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
		request.PduSessionId = 10
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

	ack, err := g.processMnToSnHandover(ranUe, request.PduSessionId)
	if err != nil {
		g.ApiLog.Errorf("Error process handover: %v", err)
		c.JSON(http.StatusInternalServerError, ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Error process handover: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, ConsoleGnbUeHandoverResponse{
		Message:       fmt.Sprintf("UE %s handover to secondary success", request.Imsi),
		UlPrimaryTeid: ack.UlPrimaryTeid,
		UlDcTeid:      ack.UlDcTeid,
	})
}

// processMnToSnHandover transfers the UE context to the Xn peer (the current
// secondary), which performs the path switch and becomes the new master.
// This gNB keeps serving its leg, now as the secondary.
func (g *Gnb) processMnToSnHandover(ranUe *RanUe, pduSessionId int64) (*XnHandoverAckMsg, error) {
	g.XnLog.Infof("Processing MN->SN handover for UE %s", ranUe.GetMobileIdentityIMSI())

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

	xnConn, err := util.TcpDialWithOptionalLocalAddress(g.xnInterface.xnDialIp, g.xnInterface.xnDialPort, "")
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

	g.XnLog.Infof("Handover complete: this gNB is now the secondary for UE %s "+
		"(UL primary TEID %s, UL DC TEID %s)", hoCtx.Imsi, ack.UlPrimaryTeid, ack.UlDcTeid)
	return &ack, nil
}

package gnb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/free-ran-ue/free-ran-ue/v2/constant"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
)

type XnPdu struct {
	Type       byte
	ImsiLength uint16
	Imsi       string
	Data       []byte
}

func NewXnPdu(imsi string, data []byte) *XnPdu {
	return &XnPdu{
		Type:       XnTypeNgap,
		ImsiLength: 0,
		Imsi:       imsi,
		Data:       data,
	}
}

func NewTypedXnPdu(xnType byte, imsi string, data []byte) *XnPdu {
	pdu := NewXnPdu(imsi, data)
	pdu.Type = xnType
	return pdu
}

func (x *XnPdu) Marshal() ([]byte, error) {
	imsiBytes := []byte(x.Imsi)

	buffer := make([]byte, 3)
	buffer[0] = x.Type
	binary.BigEndian.PutUint16(buffer[1:], uint16(len(imsiBytes)))

	buffer = append(buffer, imsiBytes...)
	buffer = append(buffer, x.Data...)

	return buffer, nil
}

func (x *XnPdu) Unmarshal(data []byte) error {
	if len(data) < 3 {
		return fmt.Errorf("data too short")
	}

	x.Type = data[0]
	x.ImsiLength = binary.BigEndian.Uint16(data[1:3])
	data = data[3:]

	if len(data) < int(x.ImsiLength) {
		return fmt.Errorf("data too short")
	}

	x.Imsi = string(data[:x.ImsiLength])
	data = data[x.ImsiLength:]

	x.Data = data

	return nil
}

func xnInterfaceProcessor(conn net.Conn, g *Gnb) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		g.XnLog.Warnf("Error reading XN packet: %v", err)
		return
	}
	g.XnLog.Tracef("Received %d bytes of XN packet: %+v", n, buffer[:n])
	g.XnLog.Debugln("Receive XN packet")

	xnPdu := XnPdu{}
	if err := xnPdu.Unmarshal(buffer[:n]); err != nil {
		g.XnLog.Errorf("Error unmarshal xn pdu: %v", err)
		return
	}
	g.XnLog.Tracef("Received XN PDU: %+v", xnPdu)
	g.XnLog.Debugln("Receive XN PDU")

	switch xnPdu.Type {
	case XnTypeHandoverRequest:
		xnHandoverRequestProcessor(g, conn, &xnPdu)
		return
	case XnTypeHandoverAck:
		g.XnLog.Warnln("Unexpected XN Handover Ack on listener")
		return
	case XnTypeForward:
		// primer wire size = 3 (header) + imsiLen + len(Data); Data is empty
		// for the primer, so leftover after it are the first framed relay bytes.
		primerSize := 3 + int(xnPdu.ImsiLength) + len(xnPdu.Data)
		leftover := []byte{}
		if n > primerSize {
			leftover = buffer[primerSize:n]
		}
		xnForwardProcessor(g, conn, &xnPdu, leftover)
		return
	}

	ngapMsg, err := message.Parse(xnPdu.Data)
	if err != nil {
		g.XnLog.Warnf("Error decoding NGAP PDU: %v", err)
		return
	}

	switch msg := ngapMsg.(type) {
	case *message.PDUSessionResourceSetupRequest:
		g.XnLog.Infoln("Processing NGAP PDU Session Resource Setup Request")
		xnPduSessionResourceSetupProcessor(g, conn, xnPdu.Imsi, msg)
	case *message.PDUSessionResourceModifyIndication:
		g.XnLog.Infoln("Processing NGAP PDU Session Resource Modify Indication")
		xnPduSessionResourceModifyIndicationProcessor(g, conn, xnPdu.Imsi, msg, xnPdu.Data)
	case *message.PDUSessionResourceModifyConfirm:
		g.XnLog.Infoln("Processing NGAP PDU Session Resource Modify Confirm")
		xnPduSessionResourceModifyConfirmProcessor(g, conn, xnPdu.Imsi, msg)
	default:
		g.XnLog.Warnf("Unknown NGAP PDU message: %T", ngapMsg)
	}
}

func buildDCQosFlowPerTNLInformationItem(dlTeid []byte, ranN3Ip string) ie.QosFlowPerTNLInformationItem {
	return ie.QosFlowPerTNLInformationItem{
		QosFlowPerTNLInformation: &ie.QosFlowPerTNLInformation{
			UPTransportLayerInformation: &ie.UPTransportLayerInformation{
				Choice: &ie.GTPTunnel{
					GTPTEID: &ie.GTPTEID{
						Value: dlTeid,
					},
					TransportLayerAddress: &ie.TransportLayerAddress{
						Value: ngapConvertIPAddressToNgap(ranN3Ip),
					},
				},
			},
			AssociatedQosFlowList: &ie.AssociatedQosFlowList{
				List: []ie.AssociatedQosFlowItem{
					{
						QosFlowIdentifier: &ie.QosFlowIdentifier{
							Value: 1,
						},
					},
				},
			},
		},
	}
}

func xnPduSessionResourceSetupProcessor(g *Gnb, conn net.Conn, imsi string, msg *message.PDUSessionResourceSetupRequest) {
	var pduSessionResourceSetupRequestTransfer ie.PDUSessionResourceSetupRequestTransfer

	if msg.PDUSessionResourceSetupListSUReq != nil {
		for _, pduSessionResourceSetupItem := range msg.PDUSessionResourceSetupListSUReq.List {
			if pduSessionResourceSetupItem.PDUSessionResourceSetupRequestTransfer == nil {
				continue
			}
			if err := ie.UnmarshalBinary(*pduSessionResourceSetupItem.PDUSessionResourceSetupRequestTransfer, &pduSessionResourceSetupRequestTransfer); err != nil {
				g.XnLog.Warnf("Error unmarshal pdu session resource setup request transfer: %v", err)
				return
			}
			g.XnLog.Tracef("Get PDUSessionResourceSetupRequestTransfer: %+v", pduSessionResourceSetupRequestTransfer)
		}
	}

	xnUe := NewXnUe(imsi, g.teidGenerator.AllocateTeid(), nil)
	g.xnUeConns.Store(xnUe, struct{}{})
	g.XnLog.Debugf("Allocated DLTEID for XnUe: %s", hex.EncodeToString(xnUe.GetDlTeid()))

	if pduSessionResourceSetupRequestTransfer.ProtocolIEs != nil {
		for _, item := range pduSessionResourceSetupRequestTransfer.ProtocolIEs.List {
			if item.AdditionalULNGUUPTNLInformation == nil || len(item.AdditionalULNGUUPTNLInformation.List) == 0 {
				continue
			}
			nguUpTnlInformation := item.AdditionalULNGUUPTNLInformation.List[0].NGUUPTNLInformation
			if nguUpTnlInformation == nil {
				continue
			}
			if gtpTunnel, ok := nguUpTnlInformation.Choice.(*ie.GTPTunnel); ok && gtpTunnel.GTPTEID != nil {
				xnUe.SetUlTeid(gtpTunnel.GTPTEID.Value)
			}
		}
	}

	// DC QoS Flow per TNL Information
	dcQosFlowPerTNLInformationItem := buildDCQosFlowPerTNLInformationItem(xnUe.GetDlTeid(), g.ranN3Ip)

	dcQosFlowPerTNLInformationMarshal, err := ie.MarshalBinary(&dcQosFlowPerTNLInformationItem)
	if err != nil {
		g.XnLog.Warnf("Error marshal dc qos flow per tnl information: %v", err)
		return
	}

	xnPdu := NewXnPdu(imsi, dcQosFlowPerTNLInformationMarshal)
	xnPduBytes, err := xnPdu.Marshal()
	if err != nil {
		g.XnLog.Warnf("Error marshal xn pdu: %v", err)
		return
	}

	n, err := conn.Write(xnPduBytes)
	if err != nil {
		g.XnLog.Warnf("Error write dc qos flow per tnl information: %v", err)
		return
	}
	g.XnLog.Tracef("Sent %d bytes of DC QoS Flow per TNL Information to XN", n)
	g.XnLog.Debugln("Send DC QoS Flow per TNL Information to XN")

	g.dlTeidToUe.Store(hex.EncodeToString(xnUe.GetDlTeid()), xnUe)
	g.XnLog.Debugf("Stored XN UE %s with DL TEID %s to dlTeidToUe", xnUe.GetIMSI(), hex.EncodeToString(xnUe.GetDlTeid()))

	g.imsiTodlTeidAndUeType.Store(imsi, dlTeidAndUeType{
		dlTeid: xnUe.GetDlTeid(),
		ueType: constant.UE_TYPE_XN,
	})
	g.XnLog.Debugf("Sent DL TEID %s to imsiTodlTeidAndUeType", hex.EncodeToString(xnUe.GetDlTeid()))
}

func xnPduSessionResourceModifyIndicationProcessor(g *Gnb, conn net.Conn, imsi string, msg *message.PDUSessionResourceModifyIndication, ngapRaw []byte) {
	if xnReleaseUeProcessor(g, conn, imsi) {
		g.XnLog.Infof("XnUe released for imsi: %s", imsi)

		xnPdu := NewXnPdu(imsi, ngapRaw)
		xnPduBytes, err := xnPdu.Marshal()
		if err != nil {
			g.XnLog.Warnf("Error marshal xn pdu: %v", err)
			return
		}

		n, err := conn.Write(xnPduBytes)
		if err != nil {
			g.XnLog.Warnf("Error write ngap pdu: %v", err)
			return
		}
		g.XnLog.Tracef("Sent %d bytes of NGAP PDU Session Resource Modify Indication to XN", n)
		g.XnLog.Debugln("Send NGAP PDU Session Resource Modify Indication to XN")

		return
	}

	if msg.PDUSessionResourceModifyListModInd == nil {
		g.XnLog.Warnf("Error pdu session resource modify indication: missing mandatory IE")
		return
	}

	itemIndex := -1
	for i, item := range msg.PDUSessionResourceModifyListModInd.List {
		if item.PDUSessionID != nil && item.PDUSessionID.Value == constant.PDU_SESSION_ID {
			itemIndex = i
			break
		}
	}
	if itemIndex == -1 || msg.PDUSessionResourceModifyListModInd.List[itemIndex].PDUSessionResourceModifyIndicationTransfer == nil {
		g.XnLog.Warnf("Error pdu session resource modify indication: pdu session %d not found", constant.PDU_SESSION_ID)
		return
	}

	var pduSessionResourceModifyIndicationTransfer ie.PDUSessionResourceModifyIndicationTransfer
	if err := ie.UnmarshalBinary(*msg.PDUSessionResourceModifyListModInd.List[itemIndex].PDUSessionResourceModifyIndicationTransfer, &pduSessionResourceModifyIndicationTransfer); err != nil {
		g.XnLog.Warnf("Error unmarshal pdu session resource modify indication transfer: %v", err)
		return
	}
	g.XnLog.Tracef("Get PDUSessionResourceModifyIndicationTransfer: %+v", pduSessionResourceModifyIndicationTransfer)

	xnUe := NewXnUe(imsi, g.teidGenerator.AllocateTeid(), nil)
	g.xnUeConns.Store(xnUe, struct{}{})
	g.XnLog.Debugf("Allocated DLTEID for XnUe: %s", hex.EncodeToString(xnUe.GetDlTeid()))

	// DC QoS Flow per TNL Information
	dcQosFlowPerTNLInformationItem := buildDCQosFlowPerTNLInformationItem(xnUe.GetDlTeid(), g.ranN3Ip)

	// Additional DL QoS Flow per TNL Information
	pduSessionResourceModifyIndicationTransfer.AdditionalDLQosFlowPerTNLInformation = &ie.QosFlowPerTNLInformationList{
		List: []ie.QosFlowPerTNLInformationItem{dcQosFlowPerTNLInformationItem},
	}

	pduSessionResourceModifyIndicationTransferMarshal, err := ie.MarshalBinary(&pduSessionResourceModifyIndicationTransfer)
	if err != nil {
		g.XnLog.Warnf("Error marshal pdu session resource modify indication transfer: %v", err)
		return
	}

	transfer := aper.OctetString(pduSessionResourceModifyIndicationTransferMarshal)
	msg.PDUSessionResourceModifyListModInd.List[itemIndex].PDUSessionResourceModifyIndicationTransfer = &transfer
	g.XnLog.Tracef("Get PDUSessionResourceModifyIndicationTransfer: %+v", pduSessionResourceModifyIndicationTransfer)

	ngapPdu, err := msg.MarshalBinary()
	if err != nil {
		g.XnLog.Warnf("Error encode ngap pdu: %v", err)
		return
	}

	xnPdu := NewXnPdu(imsi, ngapPdu)
	xnPduBytes, err := xnPdu.Marshal()
	if err != nil {
		g.XnLog.Warnf("Error marshal xn pdu: %v", err)
		return
	}

	n, err := conn.Write(xnPduBytes)
	if err != nil {
		g.XnLog.Warnf("Error write ngap pdu: %v", err)
		return
	}
	g.XnLog.Tracef("Sent %d bytes of NGAP PDU Session Resource Modify Indication to XN", n)
	g.XnLog.Debugln("Send NGAP PDU Session Resource Modify Indication to XN")
}

func xnPduSessionResourceModifyConfirmProcessor(g *Gnb, conn net.Conn, imsi string, msg *message.PDUSessionResourceModifyConfirm) {
	if msg.PDUSessionResourceModifyListModCfm == nil {
		g.XnLog.Warnf("Error pdu session resource modify confirm: missing mandatory IE")
		return
	}

	var pduSessionResourceModifyConfirmTransferRaw *aper.OctetString
	for _, pduSessionResourceModifyItem := range msg.PDUSessionResourceModifyListModCfm.List {
		if pduSessionResourceModifyItem.PDUSessionID != nil && pduSessionResourceModifyItem.PDUSessionID.Value == constant.PDU_SESSION_ID {
			pduSessionResourceModifyConfirmTransferRaw = pduSessionResourceModifyItem.PDUSessionResourceModifyConfirmTransfer
		}
	}
	if pduSessionResourceModifyConfirmTransferRaw == nil {
		g.XnLog.Warnf("Error pdu session resource modify confirm: pdu session %d not found", constant.PDU_SESSION_ID)
		return
	}

	pduSessionResourceModifyConfirmTransfer := ie.PDUSessionResourceModifyConfirmTransfer{}
	if err := ie.UnmarshalBinary(*pduSessionResourceModifyConfirmTransferRaw, &pduSessionResourceModifyConfirmTransfer); err != nil {
		g.XnLog.Warnf("Error unmarshal pdu session resource modify confirm transfer: %v", err)
		return
	}
	g.XnLog.Tracef("Get PDUSessionResourceModifyConfirmTransfer: %+v", pduSessionResourceModifyConfirmTransfer)

	var xnUe *XnUe

	g.xnUeConns.Range(func(key, value interface{}) bool {
		if key.(*XnUe).GetIMSI() == imsi {
			xnUe = key.(*XnUe)
			return false
		}
		return true
	})

	if xnUe == nil {
		g.XnLog.Warnf("XnUe not found for imsi: %s", imsi)
		return
	}

	if pduSessionResourceModifyConfirmTransfer.ULNGUUPTNLInformation != nil {
		if gtpTunnel, ok := pduSessionResourceModifyConfirmTransfer.ULNGUUPTNLInformation.Choice.(*ie.GTPTunnel); ok && gtpTunnel.GTPTEID != nil {
			xnUe.SetUlTeid(gtpTunnel.GTPTEID.Value)
		}
	}

	xnPdu := NewXnPdu(imsi, []byte{})
	xnPduBytes, err := xnPdu.Marshal()
	if err != nil {
		g.XnLog.Warnf("Error marshal xn pdu: %v", err)
		return
	}

	n, err := conn.Write(xnPduBytes)
	if err != nil {
		g.XnLog.Warnf("Error write ngap pdu: %v", err)
		return
	}
	g.XnLog.Tracef("Sent %d bytes of NGAP PDU Session Resource Modify Confirm to XN", n)
	g.XnLog.Debugln("Send NGAP PDU Session Resource Modify Confirm to XN")

	g.dlTeidToUe.Store(hex.EncodeToString(xnUe.GetDlTeid()), xnUe)
	g.XnLog.Debugf("Stored XN UE %s with DL TEID %s to dlTeidToUe", xnUe.GetIMSI(), hex.EncodeToString(xnUe.GetDlTeid()))

	g.imsiTodlTeidAndUeType.Store(imsi, dlTeidAndUeType{
		dlTeid: xnUe.GetDlTeid(),
		ueType: constant.UE_TYPE_XN,
	})
	g.XnLog.Debugf("Sent DL TEID %s to imsiTodlTeidAndUeType", hex.EncodeToString(xnUe.GetDlTeid()))
}

func xnReleaseUeProcessor(g *Gnb, conn net.Conn, imsi string) bool {
	var xnUe *XnUe

	g.xnUeConns.Range(func(key, value interface{}) bool {
		if key.(*XnUe).GetIMSI() == imsi {
			xnUe = key.(*XnUe)
			return false
		}
		return true
	})

	if xnUe == nil {
		return false
	}

	g.dlTeidToUe.Delete(hex.EncodeToString(xnUe.GetDlTeid()))
	g.XnLog.Debugf("Deleted XN UE %s with DL TEID %s from dlTeidToUe", xnUe.GetIMSI(), hex.EncodeToString(xnUe.GetDlTeid()))

	g.addressToUe.Delete(xnUe.GetDataPlaneAddress().String())
	g.XnLog.Debugf("Deleted XN UE %s with data plane address %s from addressToUe", xnUe.GetIMSI(), xnUe.GetDataPlaneAddress().String())

	xnUe.Release(g.teidGenerator)
	g.XnLog.Debugf("Released XN UE %s with DL TEID %s", xnUe.GetIMSI(), hex.EncodeToString(xnUe.GetDlTeid()))

	g.xnUeConns.Delete(xnUe)
	g.XnLog.Debugf("Deleted XN UE %s from xnUeConns", xnUe.GetIMSI())

	return true
}

// xnForwardProcessor receives forwarded DL from the source MN and buffers it
// per IMSI until the UE attaches here, then flushForwardedPackets drains it
// ahead of live traffic. The first frame is parsed; the rest stream off conn.
func xnForwardProcessor(g *Gnb, conn net.Conn, first *XnPdu, leftover []byte) {
	g.XnLog.Infof("Receiving forwarded DL for UE %s", first.Imsi)
	// The primer arrived unframed via the listener dispatch. Any bytes the
	// listener read past the primer are the first framed relay bytes; splice
	// them back in front of the connection stream so none are lost.
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(leftover), conn))
	lenBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(reader, lenBuf); err != nil {
			g.XnLog.Infof("Forwarded DL stream for UE %s ended: %v", first.Imsi, err)
			return
		}
		frameLen := binary.BigEndian.Uint32(lenBuf)
		if frameLen == 0 || frameLen > 65536 {
			g.XnLog.Warnf("Invalid forwarded frame length %d, closing stream", frameLen)
			return
		}
		body := make([]byte, frameLen)
		if _, err := io.ReadFull(reader, body); err != nil {
			g.XnLog.Infof("Forwarded DL stream for UE %s ended mid-frame: %v", first.Imsi, err)
			return
		}
		pdu := XnPdu{}
		if err := pdu.Unmarshal(body); err != nil {
			g.XnLog.Warnf("Error unmarshal forwarded frame: %v", err)
			continue
		}
		if pdu.Type != XnTypeForward {
			g.XnLog.Warnf("Unexpected frame type %d on forward stream", pdu.Type)
			continue
		}
		g.bufferForwardedPacket(pdu.Imsi, pdu.Data)
	}
}

// writeFramedXnPdu sends a length-prefixed XnPdu over a stream connection so
// the receiver can recover message boundaries (raw TCP has none).
func writeFramedXnPdu(conn net.Conn, pdu *XnPdu) error {
	body, err := pdu.Marshal()
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	_, err = conn.Write(frame)
	return err
}

type forwardQueue struct {
	mu      sync.Mutex
	ready   bool
	addr    *net.UDPAddr
	packets [][]byte
}

// bufferForwardedPacket appends under the queue lock, or delivers live if the
// buffer has already been flushed. One lock guards ready+packets so a packet
// can never land in an already-drained queue.
func (g *Gnb) bufferForwardedPacket(imsi string, payload []byte) {
	if len(payload) == 0 {
		return // primer frame
	}
	actual, _ := g.forwardBuffer.LoadOrStore(imsi, &forwardQueue{})
	q := actual.(*forwardQueue)
	q.mu.Lock()
	if q.ready {
		addr := q.addr
		q.mu.Unlock()
		if addr != nil {
			if _, err := g.ranDataPlaneServer.WriteToUDP(payload, addr); err != nil {
				g.XnLog.Warnf("Error delivering live forwarded packet: %v", err)
			}
		}
		return
	}
	q.packets = append(q.packets, payload)
	q.mu.Unlock()
}

// flushForwardedPackets drains buffered payloads in order and flips ready
// under the same lock, so no packet appended concurrently is lost.
func (g *Gnb) flushForwardedPackets(imsi string, addr *net.UDPAddr) {
	actual, _ := g.forwardBuffer.LoadOrStore(imsi, &forwardQueue{})
	q := actual.(*forwardQueue)
	q.mu.Lock()
	pkts := q.packets
	q.packets = nil
	q.addr = addr
	q.ready = true
	for _, p := range pkts {
		if _, err := g.ranDataPlaneServer.WriteToUDP(p, addr); err != nil {
			g.XnLog.Warnf("Error flushing forwarded packet: %v", err)
		}
	}
	q.mu.Unlock()
	g.XnLog.Infof("Flushed %d forwarded packets for UE %s", len(pkts), imsi)
}

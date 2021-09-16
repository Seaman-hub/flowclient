/*
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy ofthe License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 */

package openflow

import (
	"fmt"
	"net"

	"github.com/Seaman-hub/flowclient/goloxi"
	ofp "github.com/Seaman-hub/flowclient/goloxi/of15"
)

// OpenFlow15 implements the 1.5 OpenFlow protocol basic methods
var OpenFlow OpenFlowProtocol

// Protocol describes the immutable part of an OpenFlow protocol version
type Protocol interface {
	String() string
	GetVersion() uint8
	DecodeMessage(data []byte) (goloxi.Message, error)
	NewHello(versionBitmap uint32) goloxi.Message
	NewEchoRequest() goloxi.Message
	NewEchoReply() goloxi.Message
	NewBarrierRequest() goloxi.Message
	NewFlowAddMatchDstIp(dstip string, regval0, regval1 uint32, pri uint16, intableid, gotableid uint8) goloxi.Message
	NewFlowDelAll(tid uint32) goloxi.Message
	NewFlowDelMatchIp(ip string, intableid uint8) goloxi.Message
}

// OpenFlowProtocol implements the basic methods for OpenFlow
type OpenFlowProtocol struct {
}

// String returns the OpenFlow protocol version as a string
func (p OpenFlowProtocol) String() string {
	return "OpenFlow 1.5"
}

// GetVersion returns the OpenFlow protocol wire version
func (p OpenFlowProtocol) GetVersion() uint8 {
	return goloxi.VERSION_1_5
}

// NewHello returns a new hello message
func (p OpenFlowProtocol) NewHello(versionBitmap uint32) goloxi.Message {
	msg := ofp.NewHello()
	elem := ofp.NewHelloElemVersionbitmap()
	elem.Length = 8
	bitmap := ofp.NewUint32()
	bitmap.Value = versionBitmap
	elem.Bitmaps = append(elem.Bitmaps, bitmap)
	msg.Elements = append(msg.Elements, elem)
	return msg
}

func (p OpenFlowProtocol) NewFlowDelAll(tid uint32) goloxi.Message {
	ethtype := ofp.NewOxmEthType()
	ethtype.SetValue(ofp.EthPIp)

	match := ofp.NewMatchV3()
	match.SetType(1)    /* OFPMT_OXM */
	match.SetLength(10) /* header + oxm  */
	match.SetOxmList([]goloxi.IOxm{ethtype})
	msg := ofp.NewFlowDelete()
	msg.SetMatch(*match)
	msg.SetTableId(tid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	msg.SetPriority(100)
	msg.SetCommand(3)
	return msg
}
func (p OpenFlowProtocol) NewFlowDelMatchIp(ip string, intableid uint8) goloxi.Message {

	log.WithField("ip", ip).Info("flow deleting")
	ipdst := ofp.NewOxmIpv4Dst()
	ipdst.SetValue(net.ParseIP(ip))

	ethtype := ofp.NewOxmEthType()
	ethtype.SetValue(ofp.EthPIp)

	match := ofp.NewMatchV3()
	match.SetType(1)    /* OFPMT_OXM */
	match.SetLength(18) /* header + oxm  */
	match.SetOxmList([]goloxi.IOxm{ethtype, ipdst})

	msg := ofp.NewFlowDelete()
	msg.SetMatch(*match)
	msg.SetTableId(intableid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	// msg.SetPriority(pri)
	msg.SetCommand(3)
	return msg
}

func (p OpenFlowProtocol) NewFlowAddMatchDstIp(dstip string, regval0, regval1 uint32, pri uint16, intableid, gotableid uint8) goloxi.Message {

	// matchipdst := ofp.NewOxmIpv4Dst()
	// matchipdst.SetValue(net.ParseIP(dstip))

	matchipdstW := ofp.NewOxmIpv4DstMasked()
	_, ipNet, err := net.ParseCIDR(dstip)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	matchipdstW.SetValue(net.IP(ipNet.IP))
	matchipdstW.SetValueMask(net.IP(ipNet.Mask))
	ethtype := ofp.NewOxmEthType()
	ethtype.SetValue(ofp.EthPIp)

	match := ofp.NewMatchV3()
	match.SetType(1)    /* OFPMT_OXM */
	match.SetLength(22) /* header + oxm  */
	match.SetOxmList([]goloxi.IOxm{ethtype, matchipdstW})

	reg0 := ofp.NewNxmReg0()
	reg0.SetValue(regval0)
	act0 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act0.SetField(reg0)
	act0.SetLen(16)

	inst1 := ofp.NewInstructionApplyActions() /* instruction type OFPIT_APPLY_ACTIONS */
	if regval1 == 0 {
		srcreg := ofp.NewOxmIdIpv4Dst()
		dstreg := ofp.NewOxmIdReg1()
		act1 := ofp.NewActionCopyField() /* action type OFPAT_COPY_FIELD */
		// act5.SetSrcOffset(2)
		// act5.SetDstOffset(16)
		act1.SetNBits(32)
		act1.SetOxmIds([]goloxi.IOxmId{srcreg, dstreg})
		act1.SetLen(24)

		inst1.SetLen(48)
		inst1.SetActions([]goloxi.IAction{act0, act1})
	} else {
		dstreg1 := ofp.NewNxmReg1()
		dstreg1.SetValue(regval1)
		act1 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
		act1.SetField(dstreg1)
		act1.SetLen(16)

		inst1.SetLen(40)
		inst1.SetActions([]goloxi.IAction{act0, act1})
	}

	inst2 := ofp.NewInstructionGotoTable()
	inst2.SetTableId(gotableid)
	inst2.SetLen(8)

	msg := ofp.NewFlowAdd()
	msg.SetMatch(*match)
	msg.SetTableId(intableid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	msg.SetPriority(pri)

	msg.SetInstructions([]ofp.IInstruction{inst1, inst2})

	return msg
}

// NewEchoRequest returns a new echo request message
func (p OpenFlowProtocol) NewEchoRequest() goloxi.Message {
	return ofp.NewEchoRequest()
}

// NewEchoReply returns a new echo reply message
func (p OpenFlowProtocol) NewEchoReply() goloxi.Message {
	return ofp.NewEchoReply()
}

// NewBarrierRequest returns a new barrier request message
func (p OpenFlowProtocol) NewBarrierRequest() goloxi.Message {
	return ofp.NewBarrierRequest()
}

// DecodeMessage parses an OpenFlow message
func (p OpenFlowProtocol) DecodeMessage(data []byte) (goloxi.Message, error) {
	return ofp.DecodeMessage(data)
}

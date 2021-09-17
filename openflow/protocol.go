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

	NewFlowDelAll(tid uint8) goloxi.Message
	NewFlowDelMatchDstIp(ip string, intableid uint8) goloxi.Message
	NewFlowDelMatchDstIpWithMask(ip string, tableid uint8) goloxi.Message
	NewFlowDelMatchDstIpWithReg(ip string, val uint32, tableid uint8) goloxi.Message
	NewFlowSetRegWithDstIp(cfg *Flowcfg) goloxi.Message
	NewFlowSetRegWithVal(cfg *Flowcfg) goloxi.Message
	NewFlowMatchVlanSetEth(cfg *Flowcfg) goloxi.Message
	NewFlowMatchRegSetEth(cfg *Flowcfg) goloxi.Message
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

func (p OpenFlowProtocol) NewFlowDelAll(tid uint8) goloxi.Message {
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
func (p OpenFlowProtocol) NewFlowDelMatchDstIp(ip string, tableid uint8) goloxi.Message {
	fmt.Printf("flow deleting match ip %s in table %d", ip, tableid)
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
	msg.SetTableId(tableid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	// msg.SetPriority(pri)
	msg.SetCommand(3)
	return msg
}

func (p OpenFlowProtocol) NewFlowDelMatchDstIpWithMask(ip string, tableid uint8) goloxi.Message {

	fmt.Printf("flow deleting match ip %s in table %d", ip, tableid)
	matchipdstW := ofp.NewOxmIpv4DstMasked()
	_, ipNet, err := net.ParseCIDR(ip)
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

	msg := ofp.NewFlowDelete()
	msg.SetMatch(*match)
	msg.SetTableId(tableid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	// msg.SetPriority(pri)
	msg.SetCommand(3)
	return msg
}

func (p OpenFlowProtocol) NewFlowDelMatchDstIpWithReg(ip string, reg0val uint32, tableid uint8) goloxi.Message {
	fmt.Printf("flow deleting match ip %s in table %d\n", ip, tableid)

	ipdst := ofp.NewOxmIpv4Dst()
	ipdst.SetValue(net.ParseIP(ip))

	ethtype := ofp.NewOxmEthType()
	ethtype.SetValue(ofp.EthPIp)

	reg0 := ofp.NewNxmReg0()
	reg0.SetValue(reg0val)

	match := ofp.NewMatchV3()
	match.SetType(1)    /* OFPMT_OXM */
	match.SetLength(30) /* header + oxm  */
	match.SetOxmList([]goloxi.IOxm{ethtype, reg0, ipdst})

	msg := ofp.NewFlowDelete()
	msg.SetMatch(*match)
	msg.SetTableId(tableid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	// msg.SetPriority(pri)
	msg.SetCommand(3)
	return msg
}

func (p OpenFlowProtocol) NewFlowSetRegWithDstIp(cfg *Flowcfg) goloxi.Message {
	matchipdstW := ofp.NewOxmIpv4DstMasked()
	_, ipNet, err := net.ParseCIDR(cfg.M.Ipdstwmask)
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
	reg0.SetValue(cfg.S.Reg0val)
	act0 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act0.SetField(reg0)
	act0.SetLen(16)

	inst1 := ofp.NewInstructionApplyActions() /* instruction type OFPIT_APPLY_ACTIONS */

	src := ofp.NewOxmIdIpv4Dst()
	dst := ofp.NewOxmIdReg1()
	act1 := ofp.NewActionCopyField() /* action type OFPAT_COPY_FIELD */
	// act5.SetSrcOffset(2)
	// act5.SetDstOffset(16)
	act1.SetNBits(32)
	act1.SetOxmIds([]goloxi.IOxmId{src, dst})
	act1.SetLen(24)

	inst1.SetLen(48)
	inst1.SetActions([]goloxi.IAction{act0, act1})

	inst2 := ofp.NewInstructionGotoTable()
	inst2.SetTableId(cfg.S.Gototable)
	inst2.SetLen(8)

	msg := ofp.NewFlowAdd()
	msg.SetMatch(*match)
	msg.SetTableId(cfg.S.Tid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	msg.SetPriority(cfg.S.Priority)

	msg.SetInstructions([]ofp.IInstruction{inst1, inst2})

	return msg
}

func (p OpenFlowProtocol) NewFlowSetRegWithVal(cfg *Flowcfg) goloxi.Message {
	matchipdstW := ofp.NewOxmIpv4DstMasked()
	_, ipNet, err := net.ParseCIDR(cfg.M.Ipdstwmask)
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
	reg0.SetValue(cfg.S.Reg0val)
	act0 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act0.SetField(reg0)
	act0.SetLen(16)

	inst1 := ofp.NewInstructionApplyActions() /* instruction type OFPIT_APPLY_ACTIONS */

	reg1 := ofp.NewNxmReg1()
	reg1.SetValue(cfg.S.Reg1val)
	act1 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act1.SetField(reg1)
	act1.SetLen(16)

	inst1.SetLen(40)
	inst1.SetActions([]goloxi.IAction{act0, act1})

	inst2 := ofp.NewInstructionGotoTable()
	inst2.SetTableId(cfg.S.Gototable)
	inst2.SetLen(8)

	msg := ofp.NewFlowAdd()
	msg.SetMatch(*match)
	msg.SetTableId(cfg.S.Tid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	msg.SetPriority(cfg.S.Priority)

	msg.SetInstructions([]ofp.IInstruction{inst1, inst2})

	return msg
}

//ovs-ofctl -OOPENFLOW15 add-flow ch-br "table=2,priority=0xc000,vlan_tci=0x1000/0x1000,ip,
//reg0=<vid>,reg1=<nexthopIP>,action=load:<dmac>->eth_dst,load:<smac>->eth_src,load:<vid>->vlan_vid,output:in_port"
func (p OpenFlowProtocol) NewFlowMatchVlanSetEth(cfg *Flowcfg) goloxi.Message {
	ethtype := ofp.NewOxmEthType()
	ethtype.SetValue(ofp.EthPIp)

	reg0 := ofp.NewNxmReg0()
	reg0.SetValue(cfg.M.Reg0val)

	reg1 := ofp.NewNxmReg1()
	reg1.SetValue(cfg.M.Reg1val)

	tci := ofp.NewNxmVlanTciMasked()
	tci.SetValue(cfg.M.Vlantci)
	tci.SetValueMask(cfg.M.Tcimask)

	match := ofp.NewMatchV3()
	match.SetType(1)    /* OFPMT_OXM */
	match.SetLength(34) /* header + oxm  */
	match.SetOxmList([]goloxi.IOxm{ethtype, tci, reg0, reg1})

	set_ethsrc := ofp.NewOxmEthSrc()
	src, _ := net.ParseMAC(cfg.S.Ethsrc)
	set_ethsrc.SetValue(src)
	act1 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act1.SetField(set_ethsrc)
	act1.SetLen(16)

	set_ethdst := ofp.NewOxmEthDst()
	dst, _ := net.ParseMAC(cfg.S.Ethdst)
	set_ethdst.SetValue(dst)
	act2 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act2.SetField(set_ethdst)
	act2.SetLen(16)

	vlan := ofp.NewOxmVlanVid()
	vlan.SetValue(0x1000 + uint16(cfg.M.Reg0val))
	act3 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act3.SetField(vlan)
	act3.SetLen(16)

	act4 := ofp.NewActionOutput()
	act4.SetPort(ofp.OFPPInPort)
	act4.SetLen(16)

	inst1 := ofp.NewInstructionApplyActions() /* instruction type OFPIT_APPLY_ACTIONS */
	inst1.SetLen(72)
	inst1.SetActions([]goloxi.IAction{act1, act2, act3, act4})

	msg := ofp.NewFlowAdd()
	msg.SetMatch(*match)
	msg.SetTableId(cfg.S.Tid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	msg.SetPriority(cfg.S.Priority)

	msg.SetInstructions([]ofp.IInstruction{inst1})

	return msg
}

//  cookie=0x0, duration=2.040s, table=1, n_packets=0, n_bytes=0, idle_age=2, priority=55,ip,reg0=0xc8,reg1=0x9090909
// actions=set_field:02:02:02:02:02:02->eth_src,set_field:01:01:01:01:01:01->eth_dst,push_vlan:0x8100,set_field:4296->vlan_vid,IN_PORT

func (p OpenFlowProtocol) NewFlowMatchRegSetEth(cfg *Flowcfg) goloxi.Message {
	ethtype := ofp.NewOxmEthType()
	ethtype.SetValue(ofp.EthPIp)

	reg0 := ofp.NewNxmReg0()
	reg0.SetValue(cfg.M.Reg0val)

	reg1 := ofp.NewNxmReg1()
	reg1.SetValue(cfg.M.Reg1val)

	match := ofp.NewMatchV3()
	match.SetType(1)    /* OFPMT_OXM */
	match.SetLength(26) /* header + oxm  */
	match.SetOxmList([]goloxi.IOxm{ethtype, reg0, reg1})

	set_ethsrc := ofp.NewOxmEthSrc()
	src, _ := net.ParseMAC(cfg.S.Ethsrc)
	set_ethsrc.SetValue(src)
	act1 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act1.SetField(set_ethsrc)
	act1.SetLen(16)

	set_ethdst := ofp.NewOxmEthDst()
	dst, _ := net.ParseMAC(cfg.S.Ethdst)
	set_ethdst.SetValue(dst)
	act2 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act2.SetField(set_ethdst)
	act2.SetLen(16)

	act3 := ofp.NewActionPushVlan() /* action type OFPAT_SET_FIELD */
	act3.SetEthertype(ofp.EthP8021Q)
	act3.SetLen(8)

	vlan := ofp.NewOxmVlanVid()
	vlan.SetValue(0x1000 + uint16(cfg.M.Reg0val))
	act4 := ofp.NewActionSetField() /* action type OFPAT_SET_FIELD */
	act4.SetField(vlan)
	act4.SetLen(16)

	act5 := ofp.NewActionOutput()
	act5.SetPort(ofp.OFPPInPort)
	act5.SetLen(16)

	inst1 := ofp.NewInstructionApplyActions() /* instruction type OFPIT_APPLY_ACTIONS */
	inst1.SetLen(80)
	inst1.SetActions([]goloxi.IAction{act1, act2, act3, act4, act5})

	msg := ofp.NewFlowAdd()
	msg.SetMatch(*match)
	msg.SetTableId(cfg.S.Tid)
	msg.SetOutPort(ofp.OFPPAny)
	msg.SetOutGroup(ofp.OFPGAny)
	msg.SetBufferId(ofp.NoBuffer)
	msg.SetCookie(0)
	msg.SetCookieMask(0)
	msg.SetPriority(cfg.S.Priority)

	msg.SetInstructions([]ofp.IInstruction{inst1})

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

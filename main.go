package main

import (
	"context"
	"fmt"

	"github.com/Seaman-hub/flowclient/openflow"
)

const (
	activeAddr = "tcp:127.0.0.1:6653"
)

type SampleController struct {
	Client *openflow.Client
}

// NewSampleController returns a simple controller using an active TCP socket connection
func NewSampleController(addr string) (*SampleController, error) {
	client, err := openflow.NewClient(addr)
	if err != nil {
		return nil, err
	}

	return &SampleController{
		Client: client,
	}, nil
}

//

func main() {
	controller, _ := NewSampleController(activeAddr)
	ctx, _ := context.WithCancel(context.Background())
	err := controller.Client.Start(ctx)
	if err != nil {
		fmt.Printf("client start error %s", err)
	}

	// delete all flows in table 0
	//ovs-ofctl -OOPENFLOW15 del-flows ch-br table=1,ip
	tableid := 1
	controller.Client.DeleteAllFlows(uint8(tableid))
	// fmt.Printf("\nDeleteAllFlows() end\n")
	// to create flow
	var cfg openflow.Flowcfg
	cfg.M.Ipdstwmask = "11.11.11.11/24"
	cfg.S.Reg0val = 100

	cfg.S.Tid = 1
	cfg.S.Gototable = 2
	//  Create flows like cookie=0x0, duration=72.118s, table=1, n_packets=0, n_bytes=0, idle_age=72, priority=0,ip,nw_dst=11.11.11.0/24
	// actions=set_field:0x64->reg0,move:NXM_OF_IP_DST[]->NXM_NX_REG1[],goto_table:2
	// controller.Client.CreateFlowSetRegWithDstIp(&cfg)
	// fmt.Printf("\nCreateFlowSetRegWithDstIp() end\n")

	// To del flows like table=1,ip,ip_dst=11.11.11.11
	// controller.Client.DeleteFlowMatchDstIp("11.11.11.11", uint8(tableid))
	// fmt.Printf("\nDeleteFlowMatchDstIp() end\n")

	// To del flows like table=1,ip,ip_dst=11.11.11.11/24
	// controller.Client.DeleteFlowMatchDstIpWithMask("11.11.11.11/24", uint8(tableid))
	// fmt.Printf("\nDeleteFlowMatchDstIpWithMask() end\n")

	// To del flows like table=1,ip,reg0=100,ip_dst=11.11.11.11
	// controller.Client.DeleteFlowMatchDstIpWithReg("11.11.11.11", 100, uint8(tableid))
	// fmt.Printf("\nDeleteFlowMatchDstIpWithReg() end\n")
	cfg.S.Reg1val = 0x08080808
	cfg.S.Priority = 55
	// /Create flows like
	// cookie=0x0, duration=6.880s, table=1, n_packets=0, n_bytes=0, idle_age=6, priority=55,ip,nw_dst=11.11.11.0/24
	// actions=set_field:0x64->reg0,set_field:0x8080808->reg1,goto_table:2
	controller.Client.CreateFlowSetRegWithVal(&cfg)
	fmt.Printf("CreateFlowSetRegWithVal() end\n")
	cfg.S.Ethdst = "01:01:01:01:01:01"
	cfg.S.Ethsrc = "02:02:02:02:02:02"
	cfg.S.Outport = 3

	cfg.M.Reg0val = 200
	cfg.M.Reg1val = 0x9090909
	// Create flows like
	// cookie=0x0, duration=2.040s, table=1, n_packets=0, n_bytes=0, idle_age=2, priority=55,ip,reg0=0xc8,reg1=0x9090909
	// actions=set_field:02:02:02:02:02:02->eth_src,set_field:01:01:01:01:01:01->eth_dst,push_vlan:0x8100,set_field:4296->vlan_vid,IN_PORT
	controller.Client.CreateFlowMatchRegSetEth(&cfg)
	fmt.Printf("CreateFlowMatchRegSetEth() end\n")

	cfg.M.Tcimask = 0x1000
	cfg.M.Vlantci = 0x1000
	// Create flows like
	// cookie=0x0, duration=1.436s, table=1, n_packets=0, n_bytes=0, idle_age=1, priority=55,ip,reg0=0xc8,reg1=0x9090909,vlan_tci=0x1000/0x1000 a
	// ctions=set_field:02:02:02:02:02:02->eth_src,set_field:01:01:01:01:01:01->eth_dst,set_field:4296->vlan_vid,IN_PORT
	controller.Client.CreateFlowMatchVlanSetEth(&cfg)
	fmt.Printf("CreateFlowMatchVlanSetEth end\n")
}

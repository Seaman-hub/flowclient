package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/Seaman-hub/flowclient/openflow"
)

const (
	activeAddr = "tcp:127.0.0.1:6653"
)

type SampleController struct {
	Client *openflow.Client
}

var selection byte
var reader *bufio.Reader

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

func execshell() {
	fmt.Println("\nDumping flows")
	c := "/usr/bin/ovs-ofctl -O OpenFlow15 dump-flows ovs-br0"
	cmd := exec.Command("/bin/bash", "-c", c)
	out, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Command finished: %s", string(out))
}

func execpause() {
	fmt.Printf("\nenter to continue, 'q' to quit:")
	selection, _ = reader.ReadByte()
	if selection == 'q' {
		fmt.Println("\nquitting......")
		os.Exit(0)
	}
}
func main() {
	controller, _ := NewSampleController(activeAddr)
	ctx, _ := context.WithCancel(context.Background())
	err := controller.Client.Start(ctx)
	if err != nil {
		fmt.Printf("client start error %s", err)
	}

	reader = bufio.NewReaderSize(os.Stdin, 1)

	var cfg openflow.Flowcfg
	cfg.M.Ipdstwmask = "11.11.11.11/24"
	cfg.M.Reg0val = 100

	cfg.S.Tid = 1
	cfg.S.Gototable = 2

	// Delete all flows in table
	controller.Client.DeleteAllFlows(cfg.S.Tid)
	fmt.Printf("\nDeleteAllFlows() in table = %d\n", cfg.S.Tid)

	execshell()
	execpause()

	//  Create flows
	// cookie=0x0, duration=72.118s, table=1, n_packets=0, n_bytes=0, idle_age=72, priority=0,ip,nw_dst=11.11.11.0/24
	// actions=set_field:0x64->reg0,move:NXM_OF_IP_DST[]->NXM_NX_REG1[],goto_table:2
	controller.Client.CreateFlowSetRegWithDstIp(&cfg)
	fmt.Printf("\nCreateFlowSetRegWithDstIp() ip dst = %s\n", cfg.M.Ipdstwmask)

	execshell()
	execpause()

	// Delete all flows in table
	controller.Client.DeleteAllFlows(cfg.S.Tid)
	fmt.Printf("\nDeleteAllFlows() in table = %d\n", cfg.S.Tid)

	execshell()
	execpause()

	cfg.S.Cookie = "0x1/0x1"
	controller.Client.CreateFlowSetRegWithDstIpCookie(&cfg)
	fmt.Printf("\nCreateFlowSetRegWithDstIpCookie() cookie = %s\n", cfg.S.Cookie)

	execshell()
	execpause()
	cfg.M.Ipdstwmask = "22.22.22.22/24"
	cfg.S.Cookie = "0x2/0x2"
	controller.Client.CreateFlowSetRegWithDstIpCookie(&cfg)
	fmt.Printf("\nCreateFlowSetRegWithDstIpCookie() cookie = %s\n", cfg.S.Cookie)

	execshell()
	execpause()
	// Delete all flows with cookie
	controller.Client.DeleteAllFlowsWithCookie(cfg.S.Tid, cfg.S.Cookie)
	fmt.Printf("\nDeleteAllFlowsWithCookie()  cookie = %s\n", cfg.S.Cookie)

	execshell()
	execpause()
	// /Create flows like
	// cookie=0x0, duration=6.880s, table=1, n_packets=0, n_bytes=0, idle_age=6, priority=55,ip,nw_dst=11.11.11.0/24
	// actions=set_field:0x64->reg0,set_field:0x8080808->reg1,goto_table:2
	cfg.S.Reg1val = 0x08080808
	cfg.S.Priority = 55
	controller.Client.CreateFlowSetRegWithVal(&cfg)
	fmt.Printf("\nCreateFlowSetRegWithVal() reg1 value = 0x%X\n", cfg.S.Reg1val)

	execshell()
	execpause()
	// To del flows like table=1,ip,ip_dst=22.22.22.22
	// controller.Client.DeleteFlowMatchDstIp("22.22.22.22", cfg.S.Tid)
	// fmt.Printf("\nDeleteFlowMatchDstIp() ip dst = 22.22.22.22\n")
	// execshell()
	// execpause()

	// controller.Client.CreateFlowSetRegWithVal(&cfg)
	// fmt.Println("\nCreateFlowSetRegWithVal() end")
	// execshell()
	// execpause()

	// To del flows like table=1,ip,ip_dst=11.11.11.11/24
	controller.Client.DeleteFlowMatchDstIpWithMask(cfg.M.Ipdstwmask, cfg.S.Tid)
	fmt.Printf("\nDeleteFlowMatchDstIpWithMask() ip dst = %s\n", cfg.M.Ipdstwmask)
	execshell()
	execpause()

	controller.Client.CreateFlowSetRegWithDstIp(&cfg)
	fmt.Printf("\nCreateFlowSetRegWithDstIp() ip dst = %s\n", cfg.M.Ipdstwmask)
	execshell()
	execpause()
	cfg.M.Ipdstwmask = "33.33.33.33/24"
	cfg.S.Priority = 2
	controller.Client.CreateFlowSetRegWithDstIp(&cfg)
	fmt.Printf("\nCreateFlowSetRegWithDstIp() ip dst = %s\n", cfg.M.Ipdstwmask)
	execshell()
	execpause()
	// To del flows like table=1,ip,reg0=100,ip_dst=11.11.11.11/24
	controller.Client.DeleteFlowMatchDstIpWithReg(cfg.M.Ipdstwmask, 100, cfg.S.Tid, 2)
	fmt.Printf("\nDeleteFlowMatchDstIpWithReg() ip dst = %s\n", cfg.M.Ipdstwmask)
	execshell()
	execpause()
	cfg.S.Ethdst = "01:01:01:01:01:01"
	cfg.S.Ethsrc = "02:02:02:02:02:02"

	cfg.M.Reg0val = 200
	cfg.M.Reg1val = 0x9090909
	// Create flows like
	// cookie=0x0, duration=2.040s, table=1, n_packets=0, n_bytes=0, idle_age=2, priority=55,ip,reg0=0xc8,reg1=0x9090909
	// actions=set_field:02:02:02:02:02:02->eth_src,set_field:01:01:01:01:01:01->eth_dst,push_vlan:0x8100,set_field:4296->vlan_vid,IN_PORT
	controller.Client.CreateFlowMatchRegSetEth(&cfg)
	fmt.Println("\nCreateFlowMatchRegSetEth() end")
	execshell()
	execpause()
	cfg.M.Vlantci = "0x1000/0x1000"
	// Create flows like
	// cookie=0x0, duration=1.436s, table=1, n_packets=0, n_bytes=0, idle_age=1, priority=55,ip,reg0=0xc8,reg1=0x9090909,vlan_tci=0x1000/0x1000
	// actions=set_field:02:02:02:02:02:02->eth_src,set_field:01:01:01:01:01:01->eth_dst,set_field:4296->vlan_vid,IN_PORT
	controller.Client.CreateFlowMatchVlanSetEth(&cfg)
	fmt.Println("\nCreateFlowMatchVlanSetEth() end")
	execshell()
	execpause()
	// delete flow as above
	controller.Client.DeleteFlowMatchVlan(&cfg)
	fmt.Printf("\nDeleteFlowMatchVlan() vlantci = %s\n", cfg.M.Vlantci)
	execshell()
}

package main

import (
	"context"
	"fmt"

	"github.com/Seaman-hub/flowclient/openflow"
)

const (
	activeAddr = "tcp:6653"
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

func main() {
	controller, _ := NewSampleController(activeAddr)
	ctx, _ := context.WithCancel(context.Background())
	err := controller.Client.Start(ctx)
	if err != nil {
		fmt.Printf("client start error %s", err)
	}
}

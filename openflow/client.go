package openflow

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Seaman-hub/flowclient/goloxi"
	ofp "github.com/Seaman-hub/flowclient/goloxi/of15"
	"github.com/skydive-project/skydive/graffiti/logging"
)

const (
	echoDuration = 3
)

var (
	// ErrContextDone is returned what the context was done or canceled
	ErrContextDone = errors.New("Context was terminated")
	// ErrConnectionTimeout is returned when a timeout was reached when trying to connect
	ErrConnectionTimeout = errors.New("Timeout while connecting")
	// ErrReaderChannelClosed is returned when the read channel was closed
	ErrReaderChannelClosed = errors.New("Reader channel was closed")
)

// Client describes an OpenFlow client
type Client struct {
	sync.RWMutex
	conn               net.Conn
	addr               string
	tlsConfig          *tls.Config
	reader             *bufio.Reader
	msgChan            chan (goloxi.Message)
	listeners          []Listener
	xid                uint32
	protocol           Protocol
	supportedProtocols []Protocol
}

// Listener defines the interface implemented by monitor listeners
type Listener interface {
	OnMessage(goloxi.Message)
}

func (c *Client) connect(addr string) (net.Conn, error) {
	var protocol string

	parts := strings.SplitN(addr, ":", 2)
	if len(parts) > 1 {
		protocol = parts[0]
		addr = parts[1]
	} else {
		return nil, fmt.Errorf("Invalid connection addr '%s'", addr)
	}

	switch protocol {
	case "tcp":
		return net.Dial(protocol, addr)
	case "ptcp":
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Printf("Failed to listen on %s %d", addr, err)
			return nil, err
		}
		fmt.Printf("Waiting for tcp connection from the bridge ...")
		conn, err := listener.Accept()
		if err != nil {
			fmt.Errorf("tcp connection from the bridge is wrong, err:%v\n", err)
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("Unsupported connection scheme '%s'", protocol)
	}
}

func (c *Client) handshake() (Protocol, error) {
	var ownBitmap uint32

	protocol := c.supportedProtocols[len(c.supportedProtocols)-1]
	for _, supportedProtocol := range c.supportedProtocols {
		ownBitmap |= 1 << supportedProtocol.GetVersion()
	}

	if err := c.SendMessage(protocol.NewHello(ownBitmap)); err != nil {
		return nil, err
	}

	header, data, err := c.readMessage()
	if err != nil {
		return nil, err
	}

	if header.Type != goloxi.OFPTHello {
		return nil, fmt.Errorf("Expected a first message of type Hello")
	}

	switch {
	case header.Version == protocol.GetVersion():
		return protocol, nil
	case header.Version < protocol.GetVersion():
		for _, protocol := range c.supportedProtocols {
			if header.Version == protocol.GetVersion() {
				return protocol, nil
			}
		}
	case header.Version > protocol.GetVersion():
		// Since OpenFlow 1.3, Hello message can include bitmaps of the supported versions.
		// If this bitmap is provided, the negotiated version is the highest one supported
		// by both sides
		if header.Version >= goloxi.VERSION_1_3 && len(data) > 8 {
			if msg, err := ofp.DecodeHello(nil, goloxi.NewDecoder(data[8:])); err == nil {
				for _, element := range msg.GetElements() {
					if peerBitmaps, ok := element.(*ofp.HelloElemVersionbitmap); ok && len(peerBitmaps.GetBitmaps()) > 0 {
						peerBitmap := peerBitmaps.GetBitmaps()[0].Value
						for i := uint8(31); i >= 0; i-- {
							if peerBitmap&(1<<i) != 0 {
								for _, supportedProtocol := range c.supportedProtocols {
									if i == supportedProtocol.GetVersion() {
										logging.GetLogger().Debugf("Negotiated version %d", i)
										return protocol, nil
									}
								}
							}
						}
					}
				}
			}
		} else {
			// Otherwise, the negotiated version is the lowest version
			return protocol, nil
		}
	}

	return nil, fmt.Errorf("Unsupported protocol version %d", protocol.GetVersion())
}

func (c *Client) handleLoop(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	echoTicker := time.NewTicker(time.Second * echoDuration)
	defer echoTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logging.GetLogger().Debugf("Context was cancelled")
			return ErrContextDone
		case <-echoTicker.C:
			c.SendEcho()
		case msg, ok := <-c.msgChan:
			if !ok {
				logging.GetLogger().Error(ErrReaderChannelClosed)
				return ErrReaderChannelClosed
			}

			c.dispatchMessage(msg)

			if msg.MessageType() == goloxi.OFPTEchoRequest {
				c.SendMessage(c.protocol.NewEchoReply())
			}
		}
	}
}

func (c *Client) dispatchMessage(msg goloxi.Message) {
	c.RLock()
	for _, listener := range c.listeners {
		listener.OnMessage(msg)
	}
	c.RUnlock()
}

func (c *Client) readMessage() (*goloxi.Header, []byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	data, err := c.reader.Peek(8)
	if err != nil {
		return nil, nil, err
	}

	header := &goloxi.Header{}
	if err := header.Decode(goloxi.NewDecoder(data)); err != nil {
		return nil, nil, err
	}

	data = make([]byte, header.Length)
	_, err = io.ReadFull(c.reader, data)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read full OpenFlow message: %s", err)
	}

	return header, data, nil
}

func (c *Client) readLoop() {
	for {
		_, data, err := c.readMessage()
		if err != nil {
			if err != io.EOF {
				logging.GetLogger().Error(err)
			}
			return
		}

		msg, err := c.protocol.DecodeMessage(data)
		if err != nil {
			continue
		}

		c.msgChan <- msg
	}
}

type barrier struct {
	c chan goloxi.Message
}

// OnMessage is called when an OpenFlow message is received
func (b *barrier) OnMessage(msg goloxi.Message) {
	if msg.MessageName() == "OFPTBarrierReply" {
		b.c <- msg
	}
}

// PrepareMessage set the message xid and increment it
func (c *Client) PrepareMessage(msg goloxi.Message) {
	msg.SetXid(atomic.AddUint32(&c.xid, 1))
}

// SendMessage sends a message to the switch
func (c *Client) SendMessage(msg goloxi.Message) error {
	if msg.GetXid() == 0 {
		c.PrepareMessage(msg)
	}

	isBarrier := msg.MessageName() == "OFPTBarrierRequest"
	encoder := goloxi.NewEncoder()

	if err := msg.Serialize(encoder); err != nil {
		return err
	}

	if isBarrier {
		b := &barrier{c: make(chan goloxi.Message, 1)}
		c.RegisterListener(b)

		_, err := c.conn.Write(encoder.Bytes())
		if err == nil {
			<-b.c
		}
		return nil
	}
	// x := msg.MessageName()
	// fmt.Printf("Message %v, data: %v \n", x, encoder.Bytes())
	_, err := c.conn.Write(encoder.Bytes())
	return err
}

// SendEcho sends an OpenFlow echo message
func (c *Client) SendEcho() error {
	return c.SendMessage(c.protocol.NewEchoRequest())
}

// RegisterListener registers a new listener of the received messages
func (c *Client) RegisterListener(listener Listener) {
	c.Lock()
	defer c.Unlock()

	c.listeners = append(c.listeners, listener)
}

// Start monitoring the OpenFlow bridge
func (c *Client) Start(ctx context.Context, cli *cli.Context) (err error) {
	c.conn, err = c.connect(c.addr)
	if err != nil {
		return err
	}

	c.reader = bufio.NewReader(c.conn)

	c.protocol, err = c.handshake()
	if err != nil {
		return err
	}

	go c.readLoop()
	go c.handleLoop(ctx)

	log.Info("Successfully connected to OpenFlow switch %s using version %d", c.addr, c.protocol.GetVersion())

	return nil
}

// Stop the client
func (c *Client) Stop() error {
	return nil
}

// GetProtocol returns the current protocol
func (c *Client) GetProtocol() Protocol {
	return c.protocol
}

// delete all flows
func (c *Client) deleteAllFlows(tid uint32) error {
	c.SendMessage(c.protocol.NewFlowDelAll(tid))
	return nil
}

func (c *Client) deleteFlowMatchIp(ip string, tableid uint8) error {
	c.SendMessage(c.protocol.NewFlowDelMatchIp(ip, tableid))
	return nil
}

func (c *Client) createFlows(dstip string, regval0, regval1 uint32, pri uint16, intableid, gotableid uint8) error {
	// Create flow
	c.SendMessage(c.protocol.NewFlowAddMatchDstIp(dstip, regval0, regval1, pri, intableid, gotableid))
	return nil
}

// NewClient returns a new OpenFlow client using either a UNIX socket or a TCP socket
func NewClient(addr string) (*Client, error) {
	protocols := []Protocol{OpenFlow}

	client := &Client{
		addr:               addr,
		msgChan:            make(chan goloxi.Message, 500),
		supportedProtocols: protocols,
	}
	return client, nil
}

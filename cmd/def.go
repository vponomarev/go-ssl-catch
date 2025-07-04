package main

import (
	"context"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	QUEUE_MAX_SIZE = 100
)

var (
	If             = flag.String("if", "", "Interface to listen for")
	Debug          = flag.Bool("debug", false, "Debug mode")
	SessionTimeout = flag.Duration("timeout", 120*time.Second, "Session tracking timeout")
	Listen         = flag.String("listen", "0.0.0.0:9999", "HTTP Listen configuration")
)

var WS = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type Addr struct {
	IP   net.IP         `json:"ip"`
	Port layers.TCPPort `json:"port"`
}

func (addr *Addr) String() string {
	return addr.IP.String() + ":" + strconv.Itoa(int(addr.Port))
}

// Session descriptor
type Session struct {
	Src     Addr
	Dest    Addr
	TCPOpts []layers.TCPOption

	RXInitSeq uint32
	RXData    []byte
	TimeStart time.Time
	TimeLast  time.Time

	IsTracked bool
	SNI       string
}
type SessionTracker struct {
	List map[string]Session
	sync.RWMutex
}

type Parser struct {
	eth    layers.Ethernet
	ip4    layers.IPv4
	ip6    layers.IPv6
	tcp    layers.TCP
	parser *gopacket.DecodingLayerParser

	Sessions SessionTracker
	Context  context.Context

	Queue  ResQueue
	DataCH chan ResData
}

type ResData struct {
	Key    string `json:"key"`
	Src    Addr   `json:"src"`
	Dest   Addr   `json:"dest"`
	OptCnt int    `json:"optCnt"`
	SNI    string `json:"SNI"`
}

type ResQueue struct {
	Id   uint32
	List []ResData

	sync.RWMutex
}

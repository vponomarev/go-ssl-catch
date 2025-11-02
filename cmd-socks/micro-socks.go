package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"log"
	"net"
)

const (
	socksVersion    byte = 5
	fragmentSize         = 200 // Размер фрагмента в байтах
	initialFragSize      = 200 // Первые N байт для фрагментации
	IFNAME               = "\\Device\\NPF_{DE608B98-5E46-423A-93F5-B24DC48DCC6F}"
)

type Fragmenter struct {
	enabled    bool
	sentBytes  int
	totalLimit int
}

var (
	RSB           RingSessionBuffer
	SerSentBuffer chan gopacket.SerializeBuffer
	paramIf       = flag.String("if", "", "Interface to listen for")
	paramPort     = flag.Int("port", 1080, "Port to listen on")
	paramTTL      = flag.Int("ttl", 7, "TTL for fake packets")
	configPath    = flag.String("config", "proxy.yml", "Path to config file, default `proxy.yml`")
)

func CaptureSessionInfo(conn net.Conn) (ok bool, si SessionInfo) {
	// Capture association
	si = SessionInfo{
		SrcIP:   conn.LocalAddr().(*net.TCPAddr).IP,
		DstIP:   conn.RemoteAddr().(*net.TCPAddr).IP,
		SrcPort: uint16(conn.LocalAddr().(*net.TCPAddr).Port),
		DstPort: uint16(conn.RemoteAddr().(*net.TCPAddr).Port),
		ISN:     0,
	}

	return RSB.Lookup(si)
}

func main() {
	flag.Parse()

	okCapture, err, chCapture := setupCapture(context.Background())
	if okCapture {
		go TrackSessions(chCapture)
	}

	portStr := fmt.Sprintf(":%d", *paramPort)

	listener, err := net.Listen("tcp", portStr)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy with fragmentation started on %v", portStr)
	//log.Printf("Fragmentation: first %d bytes in %d-byte chunks", initialFragSize, fragmentSize)

	var CntNo uint32 = 1
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[%d] AcceptConnection error: %v", CntNo, err)
			continue
		}

		//log.Printf("[%d] New connection from: %s", CntNo, conn.RemoteAddr())
		inst := Socks5{
			clientConn: conn,
			UniqNo:     CntNo,
		}
		CntNo++
		go inst.AcceptConnection()
	}
}

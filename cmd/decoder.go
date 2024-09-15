package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"reflect"
	"time"
)

func (p *Parser) DecodePacket(pkt gopacket.Packet) (r ResData, rok bool, err error) {

	// Detect IPv4 Layer
	ip4Layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		// Skip packet, we don't need it
		return
	}

	ip4, _ := ip4Layer.(*layers.IPv4)

	// Detect TCP Layer
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		// Check for UDP
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return
		}

		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == 53 {
			//fmt.Println("UDP catch:", ip4.SrcIP, udp.SrcPort, "=>", ip4.DstIP, udp.DstPort)

			appLayer := pkt.ApplicationLayer()
			if appLayer == nil {
				// TODO: Add error handler
				// Strange layer error, skip packet
				return
			}

			if reflect.TypeOf(appLayer).String() != "*layers.DNS" {
				return
			}

			dns := appLayer.(*layers.DNS)
			if dns.OpCode == layers.DNSOpCodeQuery && dns.ResponseCode == layers.DNSResponseCodeNoErr && dns.ANCount > 0 {
				for _, ans := range dns.Answers {
					//fmt.Println(ans)
					if ans.Type == layers.DNSTypeA {
						//fmt.Println("DNS RESP:", string(dns.Questions[0].Name), "=>", string(ans.Name), ans.IP.String())
						log.WithFields(log.Fields{"type": "dns-response", "domain": string(dns.Questions[0].Name), "answer": string(ans.Name), "answer-ip": ans.IP.String()}).Info()
					}
				}
			}

		}

		// Skip packet, we don't need it
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	// Session key
	var key string
	if ipIsGT(ip4.SrcIP, ip4.DstIP) {
		key = fmt.Sprintf("%s:%d:%s:%d", ip4.DstIP.String(), tcp.DstPort, ip4.SrcIP.String(), tcp.SrcPort)
	} else {
		key = fmt.Sprintf("%s:%d:%s:%d", ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort)
	}

	// Register new session
	if tcp.SYN && !tcp.ACK {
		s := Session{
			RXInitSeq: tcp.Seq,
			RXData:    nil,
			T:         time.Now(),
			Src: Addr{
				IP:   ip4.SrcIP,
				Port: tcp.SrcPort,
			},
			Dest: Addr{
				IP:   ip4.DstIP,
				Port: tcp.DstPort,
			},
			TCPOpts: tcp.Options,
		}

		p.RegisterSession(key, s)

		if *Debug {
			log.WithFields(log.Fields{"type": "registerSession", "key": key}).Debug()
		}
		return
	}

	// Check if we track this flow
	s, ok := p.GetSession(key)

	// Skip if flow is not tracked
	if !ok {
		return
	}

	// Stop session tracking on RST packet on any direction
	if tcp.RST {
		// TODO: Optionally notify about strage behaviour
		p.RemoveSession(key)
		return
	}

	// Skip if this is not client=>server packet
	if !ip4.SrcIP.Equal(s.Src.IP) {
		return
	}

	// TODO: Optionally make full init sequence analysis (SYN/SYN+ACK/ACK) if required

	appLayer := pkt.ApplicationLayer()
	if appLayer == nil {
		// TODO: Add error handler
		// Strange layer error, skip packet
		return
	}

	// Check for minimal payload length
	if len(appLayer.Payload()) < 5 {
		// SSL packet header is too short, possibly Window size games. This is not normal.
		// Stop analysis
		// TODO: Possibly inform upstream layer about this issue
		p.RemoveSession(key)
		return
	}

	// Got packet, detect SSL
	rok, sni := detectHandshake(appLayer.Payload())

	if rok {
		r = ResData{
			Src:    s.Src,
			Dest:   s.Dest,
			OptCnt: len(s.TCPOpts),
			SNI:    sni,
		}
	} else {
		if *Debug {
			log.WithFields(log.Fields{"type": "removeSession", "key": key}).Debug("Session is not SSL session")
		}
	}
	// Remove session from tracking
	p.RemoveSession(key)

	return
}

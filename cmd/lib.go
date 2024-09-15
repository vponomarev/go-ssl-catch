package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/alabianca/dnsPacket"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

func detectHandshake(data []byte) (found bool, sni string) {
	// Too short
	if len(data) < 20 {
		return false, ""
	}

	if !(data[0] == 0x16) && (data[1] == 0x03) && (data[2] == 0x01) {
		// Not SSL magic header
		return false, ""
	}

	// SSL magic key is found
	// TODO: Deep client Hello analysis
	pktLen := int(data[3])*256 + int(data[4])

	offset := int(5)

	// Process only Client Hello
	if data[offset] != 0x01 {
		return true, ""
	}
	offset++
	handshakeLen := int(data[offset])*256*256 + int(data[offset+1])*256 + int(data[offset+2])
	offset += 3

	tlsVersion := int(data[offset])*256 + int(data[offset+1])
	offset += 2

	// Random
	offset += 32

	if len(data) < offset+6 {
		return false, ""
	}

	sessionIdLength := int(data[offset])
	offset += 1 + sessionIdLength

	if len(data) < offset+5 {
		return false, ""
	}

	csLength := int(data[offset])*256 + int(data[offset+1])
	offset += 2 + csLength

	if len(data) < offset {
		return false, ""
	}

	cmLength := int(data[offset])
	offset += 1 + cmLength

	if len(data) < offset+2 {
		return false, ""
	}

	extLen := int(data[offset])*256 + int(data[offset])
	offset += 2

	if offset+extLen > len(data) {
		// INVALID Extensions len
		return true, ""
	}

	if false {
		fmt.Println(pktLen, handshakeLen, tlsVersion)
	}

	ox := 0
	for {
		ext, extType, ox2, isLast := getNextExtension(data[offset+ox:], ox)
		ox = ox2

		if extType == 0 {
			d, _, e := decodeSNI(ext)
			if e == nil {
				//fmt.Println("SNI: ", d)
				sni = d
			}
		}

		if false {
			fmt.Println(ext, extType, offset)
		}

		if isLast {
			break
		}
	}

	return true, sni
}

// DECODE Extension type = 0 (server_name)
func decodeSNI(data []byte) (domain string, t int, err error) {
	if len(data) < 6 {
		return "", 0, fmt.Errorf("TOO_SHORT")
	}
	llen := int(data[0] + data[1])
	if len(data) != llen+2 {
		return "", 0, fmt.Errorf("INVALID_LIST_LEN")
	}
	t = int(data[2])
	l := int(data[3])*256 + int(data[4])

	if len(data) != l+5 {
		return "", 0, fmt.Errorf("INVALID_NAME_LEN")
	}
	return string(data[5:]), t, nil
}

func getNextExtension(data []byte, offset int) (out []byte, t int, newOffset int, isLast bool) {
	if len(data) < offset+4 {
		out = []byte{}
		t = -1
		newOffset += len(data)
		isLast = true
		return
	}

	t = int(data[offset+0])*256 + int(data[offset+1])
	l := int(data[offset+2])*256 + int(data[offset+3])

	if offset+l+4 > len(data) {
		out = data[offset+4:]
		isLast = true
		return
	}

	out = data[offset+4 : offset+4+l]
	newOffset = offset + 4 + l
	if newOffset >= len(data) {
		isLast = true
	}
	return
}

func ipIsGT(ip1, ip2 net.IP) bool {
	for k := range ip1 {
		if ip1[k] > ip2[k] {
			return true
		}
	}
	return false
}

func (p *Parser) Init(ctx context.Context) {
	// Allocate MAP for session tracking
	p.Sessions.List = make(map[string]Session, 1024)
	p.Context = ctx
	p.DataCH = make(chan ResData)
}

func (p *Parser) RegisterSession(key string, s Session) {
	p.Sessions.Lock()
	p.Sessions.List[key] = s
	p.Sessions.Unlock()

}

func (p *Parser) RemoveSession(key string) {
	p.Sessions.Lock()
	delete(p.Sessions.List, key)
	p.Sessions.Unlock()
}

func (p *Parser) GetSession(key string) (s Session, ok bool) {
	p.Sessions.Lock()
	s, ok = p.Sessions.List[key]
	p.Sessions.Unlock()
	return
}

func (p *Parser) SessionTimeouter() {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			p.Sessions.Lock()
			for sk, sv := range p.Sessions.List {
				if time.Now().After(sv.T.Add(*SessionTimeout)) {
					delete(p.Sessions.List, sk)
				}
			}
			p.Sessions.Unlock()
		case <-p.Context.Done():
			ticker.Stop()
			return
		}
	}
}

func (p *Parser) QueueReceiver() {
	for {
		select {
		case r := <-p.DataCH:
			log.WithFields(log.Fields{"type": "event", "srcIP": r.Src.IP.String(), "srcPort": uint16(r.Src.Port), "dstIP": r.Dest.IP.String(), "dstPort": uint16(r.Dest.Port), "optCount": r.OptCnt, "SNI": r.SNI}).Info("SSL Handshake found")

			// Push data into queue
			p.Queue.Lock()
			skipCnt := 0
			if len(p.Queue.List) > QUEUE_MAX_SIZE {
				skipCnt++
			}
			p.Queue.List = append(p.Queue.List[skipCnt:], r)
			p.Queue.Id++
			p.Queue.Unlock()

		case <-p.Context.Done():
			return
		}
	}
}

func printUsage() {
	fmt.Printf("----\nList of available interfaces:\n")

	// Scan for device list
	devList, err := pcap.FindAllDevs()
	if err != nil {
		log.Errorf("Error retrieving interface list: ", err)
		return
	}

	for _, dev := range devList {
		var ipList []net.IP
		for _, ia := range dev.Addresses {
			ipList = append(ipList, ia.IP)
		}

		fmt.Printf("* Interface: [%s] IP: %v\n", dev.Name, ipList)
	}

	fmt.Printf("----\ngo-ssl-cache usage:\n")
	flag.PrintDefaults()

}

func detectDNS(data []byte) {
	p := dnsPacket.Decode(data)
	fmt.Println(p)
}

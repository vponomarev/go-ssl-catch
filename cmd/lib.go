package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

func detectHandshake(data []byte) bool {
	// Too short
	if len(data) < 10 {
		return false
	}

	if (data[0] == 0x16) && (data[1] == 0x03) && (data[2] == 0x01) {
		// SSL magic key is found
		// TODO: Deep client Hello analysis
		return true
	}
	return false
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
	p.Sessions.RLock()
	p.Sessions.List[key] = s
	p.Sessions.RUnlock()

}

func (p *Parser) RemoveSession(key string) {
	p.Sessions.RLock()
	delete(p.Sessions.List, key)
	p.Sessions.RUnlock()
}

func (p *Parser) GetSession(key string) (s Session, ok bool) {
	p.Sessions.RLock()
	s, ok = p.Sessions.List[key]
	p.Sessions.RUnlock()
	return
}

func (p *Parser) SessionTimeouter() {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			p.Sessions.RLock()
			for sk, sv := range p.Sessions.List {
				if time.Now().After(sv.T.Add(*SessionTimeout)) {
					delete(p.Sessions.List, sk)
				}
			}
			p.Sessions.RUnlock()
		case <-p.Context.Done():
			ticker.Stop()
			return
		}
	}
}

func (p *Parser) QueueReceiver() {
	for {
		select {
			case r := <- p.DataCH:
				log.WithFields(log.Fields{"type": "event", "srcIP": r.Src.IP.String(), "srcPort": uint16(r.Src.Port), "dstIP": r.Dest.IP.String(), "dstPort": uint16(r.Dest.Port), "optCount": r.OptCnt}).Info("SSL Handshake found")

				// Push data into queue
				p.Queue.RLock()
				skipCnt := 0
				if len(p.Queue.List) > QUEUE_MAX_SIZE {
					skipCnt++
				}
				p.Queue.List = append(p.Queue.List[skipCnt:], r)
				p.Queue.Id++
				p.Queue.RUnlock()

		case <- p.Context.Done():
				return
		}
	}
}

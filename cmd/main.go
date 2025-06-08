package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
)

func main() {
	ctx := context.Background()
	ctxWithCancel, cancelFunction := context.WithCancel(ctx)

	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	// Check if interface is specified. Print usage if no and exit
	if *If == "" {
		printUsage()
		return
	}

	// Scan for device list
	devList, err := pcap.FindAllDevs()
	ok := false
	for _, dev := range devList {
		if dev.Name == *If {
			ok = true
			break
		}
	}
	if !ok {
		log.WithFields(log.Fields{"type": "startup", "interface": *If}).Fatal("Unknown interface")
	}

	handle, err := pcap.OpenLive(*If, 9000, true, pcap.BlockForever)
	if err != nil {
		log.WithFields(log.Fields{"type": "startup", "interface": *If}).Fatal("Error listening interface")
		return
	}
	log.WithFields(log.Fields{"type": "startup", "interface": *If}).Warn("Starting listening on interface")

	pSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pChan := pSource.Packets()

	// Start OS TERMINATE REQUEST processor
	cOsTerminate := make(chan os.Signal, 1)
	signal.Notify(cOsTerminate, os.Interrupt)

	// Define parser
	p := Parser{}
	p.Init(ctxWithCancel)

	// Run timeout processor
	go p.SessionTimeouter()

	// Run queue receiver
	go p.QueueReceiver()

	// Run HTTP Server
	// TODO: Error handling
	go p.serveHTTP()

	pNum := 0
	// Infinite loop
	for {
		select {
		case pkt := <-pChan:
			pNum++
			r, ok, err := p.DecodePacket(pkt)
			if ok {
				// Send result into processing channel
				p.DataCH <- r
			} else {
				if err != nil {
					fmt.Println(err)
				}
			}
		case <-cOsTerminate:
			// Close context
			cancelFunction()
			log.WithFields(log.Fields{"type": "shutdown"}).Warn("OS Shutdown request")
			return
		}
	}
}

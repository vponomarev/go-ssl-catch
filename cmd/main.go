package main

import (
	"context"
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

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	// Scan for device list
	devList, err := pcap.FindAllDevs()
	for _, dev := range devList {
		fmt.Println("IFName: ", dev.Name, "IFAddr: ", dev.Addresses)
	}

	handle, err := pcap.OpenLive(*If, 1500, true, pcap.BlockForever)
	if err != nil {
		log.WithFields(log.Fields{"type": "startup", "interface": *If}).Fatal("Error listening interface")
		return
	}
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

	// Infinite loop
	for {
		select {
		case pkt := <-pChan:
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

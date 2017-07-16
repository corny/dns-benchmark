package main

import (
	"time"

	"os"

	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const timeSlots = 100 // Slots for 0..99 ms

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "filename.pcap")
		os.Exit(1)
	}

	// Open file
	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Maps and counters
	ids := make(map[uint16]time.Time)
	missesCount := 0
	requestIPv4Count := 0
	requestIPv6Count := 0
	responseCount := 0
	timeStats := make([]uint, timeSlots)
	nameStats := make(map[string]uint)
	var startTime, endTime time.Time

	// Process the packets
	for packet := range gopacket.NewPacketSource(handle, handle.LinkType()).Packets() {
		if layer := packet.Layer(layers.LayerTypeDNS); layer != nil {
			dnsPacket := layer.(*layers.DNS)

			if dnsPacket.OpCode != layers.DNSOpCodeQuery {
				continue
			}

			if dnsPacket.QR {
				// DNS response
				responseCount++
				requestTime, found := ids[dnsPacket.ID]
				if !found {
					missesCount++
					continue
				}
				delete(ids, dnsPacket.ID)

				duration := uint(packet.Metadata().Timestamp.Sub(requestTime) / time.Millisecond)
				if duration >= timeSlots {
					duration = timeSlots - 1
				}
				timeStats[duration]++
			} else {
				// DNS request
				if packet.Layer(layers.LayerTypeIPv6) != nil {
					requestIPv6Count++
				} else {
					requestIPv4Count++
				}

				ids[dnsPacket.ID] = packet.Metadata().Timestamp
				nameStats[string(dnsPacket.Questions[0].Name)]++

				if startTime.IsZero() {
					startTime = packet.Metadata().Timestamp
				}
				endTime = packet.Metadata().Timestamp
			}
		}
	}

	// Print the results
	fmt.Printf("%d requests, %d responses, %d missing requests, %d missing responses\n\n", requestIPv4Count+requestIPv6Count, responseCount, missesCount, len(ids))

	minutes := float64(endTime.Sub(startTime)) / float64(time.Minute)

	fmt.Printf("started:         %v\n", startTime)
	fmt.Printf("finished:        %v\n", endTime)
	fmt.Printf("measured period: %v seconds\n", endTime.Sub(startTime))
	fmt.Printf("IPv4 requests:   %v (%f rpm)\n", requestIPv4Count, float64(requestIPv4Count)/minutes)
	fmt.Printf("IPv6 requests:   %v (%f rpm)\n", requestIPv6Count, float64(requestIPv6Count)/minutes)

	fmt.Printf("\nrequests per round time:\n")
	for ms, count := range timeStats {
		if count > 0 {
			fmt.Printf("%02dms %6d %6.2f %%\n", ms, count, (100 * float64(count) / float64(responseCount)))
		}
	}
	for name, count := range nameStats {
		fmt.Printf("%5d %s\n", count, name)
	}
}

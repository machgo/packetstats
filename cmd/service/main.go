package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/machgo/packetstats/pkg/config"
	"github.com/machgo/packetstats/pkg/output"
)

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

var lock = sync.RWMutex{}

const TCP = "TCP"
const UDP = "UDP"

// do flow recording on tcp / udp base.
// record the packets/bytes A->B and B->A

type Flow struct {
	IPA, IPB             net.IP
	Layer4Type           string
	PortA, PortB         int
	PacketsAB, PacketsBA int
	BytesAB, BytesBA     int
	FirstPacket          time.Time
	LastPacket           time.Time
}

// source and destination label for flows are not good, because what is source and what is destination?
// maybe better to use A and B

func main() {
	fmt.Println(config.GetInstance())
	device := config.GetInstance().Device

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	output.Test()

	counter := 0
	flows := make(map[string]Flow)

	go manageFlows(flows)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// printPacketInfo(packet)
		flowKey, o := getFlowKey(packet)
		lock.Lock()
		if val, exists := flows[flowKey]; exists {
			val.BytesAB += o.BytesAB
			val.BytesBA += o.BytesBA
			val.PacketsAB += o.PacketsBA
			val.PacketsBA += o.PacketsAB
			val.LastPacket = time.Now()
			flows[flowKey] = val
		} else {
			o.FirstPacket = time.Now()
			o.LastPacket = o.FirstPacket
			flows[flowKey] = o
		}
		lock.Unlock()
		counter++

		// if counter > 100 {
		// 	counter = 0
		// 	bs, _ := json.Marshal(flows)
		// 	fmt.Println(string(bs))

		// }
	}
}

func manageFlows(data map[string]Flow) {
	for {
		now := time.Now()
		lock.Lock()
		for k, v := range data {
			if now.After(v.FirstPacket.Add(time.Second * 10)) {
				fmt.Printf("found old flow, flowmapsize: %d\n", len(data))
				delete(data, k)
			}
		}
		lock.Unlock()

		time.Sleep(10000)
	}
}

func getFlowKey(packet gopacket.Packet) (string, Flow) {
	key := ""
	inverse := false
	o := Flow{}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.SrcIP.String() > ip.DstIP.String() {
			inverse = true
			key = fmt.Sprintf("%s%s", ip.DstIP, ip.SrcIP)
			o.IPA = ip.DstIP
			o.IPB = ip.SrcIP
			o.BytesBA = packet.Metadata().CaptureLength
			o.PacketsBA = 1
		} else {
			key = fmt.Sprintf("%s%s", ip.SrcIP, ip.DstIP)
			o.IPA = ip.SrcIP
			o.IPB = ip.DstIP
			o.BytesAB = packet.Metadata().CaptureLength
			o.PacketsAB = 1
		}
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		o.Layer4Type = TCP
		if inverse {
			key = fmt.Sprintf("%s%s%d%d", key, TCP, tcp.DstPort, tcp.SrcPort)
			o.PortA = int(tcp.DstPort)
			o.PortB = int(tcp.SrcPort)
		} else {
			key = fmt.Sprintf("%s%s%d%d", key, TCP, tcp.SrcPort, tcp.DstPort)
			o.PortA = int(tcp.SrcPort)
			o.PortB = int(tcp.DstPort)
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		o.Layer4Type = UDP
		if inverse {
			key = fmt.Sprintf("%s%s%d%d", key, UDP, udp.DstPort, udp.SrcPort)
			o.PortA = int(udp.DstPort)
			o.PortB = int(udp.SrcPort)
		} else {
			key = fmt.Sprintf("%s%s%d%d", key, UDP, udp.SrcPort, udp.DstPort)
			o.PortA = int(udp.SrcPort)
			o.PortB = int(udp.DstPort)
		}
	}
	return key, o
}

func printPacketInfo(packet gopacket.Packet) {

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("udp layer detected.")
		udp, _ := udpLayer.(*layers.UDP)

		fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		fmt.Println()
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		fmt.Println("dns layer detected.")
		dns, _ := dnsLayer.(*layers.DNS)
		fmt.Println(dns.Contents)
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())

		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

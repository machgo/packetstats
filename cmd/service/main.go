package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/machgo/packetstats/pkg/config"
	"github.com/machgo/packetstats/pkg/flow"
	"github.com/machgo/packetstats/pkg/output"
	"github.com/machgo/packetstats/pkg/vpn"
)

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	hostname    string
)

var lock = sync.RWMutex{}

const TCP = "TCP"
const UDP = "UDP"

func main() {

	go vpn.GetVPNSessions()

	hostname, _ = os.Hostname()
	fmt.Println(config.GetInstance())
	device := config.GetInstance().Device

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	counter := 0
	flows := make(map[string]flow.Flow)

	publish := make(chan flow.Flow, 10)

	go manageFlows(flows, publish)
	go output.PublishMessages(publish)

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

func manageFlows(data map[string]flow.Flow, publish chan<- flow.Flow) {
	for {
		now := time.Now()
		lock.Lock()
		for k, v := range data {
			if now.After(v.FirstPacket.Add(time.Second * 60)) {
				fmt.Printf("found old flow, flowmapsize: %d\n", len(data))
				publish <- v
				delete(data, k)
			}
		}
		lock.Unlock()

		time.Sleep(10000)
	}
}

func getFlowKey(packet gopacket.Packet) (string, flow.Flow) {
	key := ""
	inverse := false
	o := flow.Flow{}

	o.Hostname = hostname
	o.Type = "flow"

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.SrcIP.String() > ip.DstIP.String() {
			inverse = true
			key = fmt.Sprintf("%s%s", ip.DstIP, ip.SrcIP)
			o.IPA = ip.DstIP.String()
			o.IPB = ip.SrcIP.String()
			o.BytesBA = packet.Metadata().CaptureLength
			o.PacketsBA = 1
		} else {
			key = fmt.Sprintf("%s%s", ip.SrcIP, ip.DstIP)
			o.IPA = ip.SrcIP.String()
			o.IPB = ip.DstIP.String()
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

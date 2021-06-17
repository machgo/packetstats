package flow

import (
	"time"
)

// do flow recording on tcp / udp base.
// record the packets/bytes A->B and B->A

type Flow struct {
	IPA, IPB             string
	Layer4Type           string
	PortA, PortB         int
	PacketsAB, PacketsBA int
	BytesAB, BytesBA     int
	FirstPacket          time.Time
	LastPacket           time.Time
	Type                 string
	Hostname             string
	VPNSession           string
}

// source and destination label for flows are not good, because what is source and what is destination?
// maybe better to use A and B

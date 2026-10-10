// Package tshark reads live packets from tshark, the command-line version of
// Wireshark. It reports one Packet per captured packet; grouping packets into
// connections is the store's job.
//
// The package has three files:
//
//	packet.go  what a Packet is
//	parse.go   turning one line of tshark output into a Packet
//	feed.go    running tshark and delivering Packets on a channel
package tshark

import (
	"strings"
	"time"
)

// IP protocol numbers, as in the IP header and in Little Snitch's log.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// TCP flag bits, as in the TCP header.
const (
	FlagFIN uint16 = 0x001 // sender is done sending
	FlagSYN uint16 = 0x002 // open a connection
	FlagRST uint16 = 0x004 // abort the connection
	FlagPSH uint16 = 0x008 // deliver the data to the app now
	FlagACK uint16 = 0x010 // acknowledges data received
)

// Packet is one captured packet.
type Packet struct {
	Time     time.Time
	Proto    uint8  // ProtoTCP or ProtoUDP
	Stream   int    // tshark's number for the connection, counted per Proto
	SrcIP    string // sender
	DstIP    string // receiver
	SrcPort  uint16
	DstPort  uint16
	Flags    uint16 // TCP flag bits; 0 for UDP
	Len      int    // size of the whole frame in bytes
	Protocol string // Wireshark's Protocol column: "TCP", "TLSv1.3", "DNS", "QUIC"
	Info     string // Wireshark's Info column: a one-line summary
	// ServerName is the host name a client asks for when it opens a TLS
	// connection. It is sent unencrypted, on the Client Hello packet only.
	ServerName string
	Outbound   bool // sent by this Mac
}

// Has reports whether all the given TCP flag bits are set.
func (p Packet) Has(flags uint16) bool { return p.Flags&flags == flags }

// FlagString names the TCP flags that are set, for example "SYN, ACK".
func (p Packet) FlagString() string {
	var set []string
	if p.Has(FlagSYN) {
		set = append(set, "SYN")
	}
	if p.Has(FlagFIN) {
		set = append(set, "FIN")
	}
	if p.Has(FlagRST) {
		set = append(set, "RST")
	}
	if p.Has(FlagPSH) {
		set = append(set, "PSH")
	}
	if p.Has(FlagACK) {
		set = append(set, "ACK")
	}
	return strings.Join(set, ", ")
}

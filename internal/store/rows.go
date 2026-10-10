// Package store keeps everything the app knows in memory and answers the
// questions the screens ask. It has no UI code.
//
// Data comes in through AddTraffic (Little Snitch rows) and AddPacket (tshark
// packets). The read methods return plain copies, safe to keep and sort.
//
// A Store is not safe for concurrent use. Call it from one place only: in
// this app, the Bubble Tea Update function.
package store

import (
	"fmt"
	"time"
)

// IP protocol numbers.
const (
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// ProtoName returns "TCP", "UDP" or "ICMP", or the number for anything else.
func ProtoName(p uint8) string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMP:
		return "ICMP"
	}
	return fmt.Sprintf("proto %d", p)
}

// AppRow is one line of the Apps pane.
type AppRow struct {
	ID       string // pass this to Hosts
	Name     string
	BytesIn  uint64
	BytesOut uint64
	Connects int
	Denies   int // connection attempts Little Snitch blocked
	Hosts    int // number of rows Hosts(ID) returns
	LastSeen time.Time
}

// Bytes is the total in both directions.
func (a AppRow) Bytes() uint64 { return a.BytesIn + a.BytesOut }

// HostRow is one line of the Hosts pane: one remote name and port that an
// app talks to. A name can resolve to several addresses, so IPs is a list.
type HostRow struct {
	Hostname string   // empty when Little Snitch reported only an address
	IPs      []string // sorted
	Port     uint16   // remote port when Outbound, local port otherwise
	Proto    uint8
	Outbound bool
	BytesIn  uint64
	BytesOut uint64
	Connects int
	Denies   int
	LastSeen time.Time
}

// Label is the host name, or the address when there is no name.
func (h HostRow) Label() string {
	if h.Hostname != "" {
		return h.Hostname
	}
	if len(h.IPs) > 0 {
		return h.IPs[0]
	}
	return "?"
}

// Bytes is the total in both directions.
func (h HostRow) Bytes() uint64 { return h.BytesIn + h.BytesOut }

// ConnKey identifies a connection: tshark numbers TCP and UDP separately.
type ConnKey struct {
	Proto  uint8
	Stream int
}

// State is where a connection is in its life.
type State int

const (
	// TCP
	StateOpening   State = iota // SYN seen, handshake not finished
	StateOpen                   // SYN, SYN-ACK and ACK seen
	StateMidstream              // already running when the capture started
	StateClosing                // one side sent FIN
	StateClosed                 // both sides sent FIN
	StateReset                  // one side sent RST
	// UDP has no handshake, so only activity can be reported.
	StateActive // a packet within the idle limit
	StateIdle
)

func (s State) String() string {
	switch s {
	case StateOpening:
		return "opening"
	case StateOpen:
		return "open"
	case StateMidstream:
		return "midstream"
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	case StateReset:
		return "reset"
	case StateActive:
		return "active"
	case StateIdle:
		return "idle"
	}
	return "unknown"
}

// Connection is one line of the Connections pane: a group of packets between
// one local port and one remote port.
type Connection struct {
	Key ConnKey // pass this to Packets
	// Protocol is the highest-level protocol seen on the connection, as
	// Wireshark names it: "TLSv1.3", "QUIC", "DNS", "HTTP". It is "TCP" or
	// "UDP" until a packet shows what runs on top.
	Protocol   string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	// ServerName is the name from the TLS Client Hello, if one was captured.
	ServerName string
	// Hostname is the best name known for the remote end: ServerName, else
	// the name Little Snitch reported for the address, else empty.
	Hostname string
	// Apps are the apps Little Snitch saw using this remote address and
	// port. Empty until Little Snitch reports it; more than one when apps
	// share a server.
	Apps     []string
	First    time.Time
	Last     time.Time
	Packets  int // all packets seen
	Kept     int // packets still in memory; Packets(Key) returns this many
	BytesIn  uint64
	BytesOut uint64
	State    State
}

// Label is the remote end as "name:port", using the address without a name.
func (c Connection) Label() string {
	host := c.Hostname
	if host == "" {
		host = c.RemoteIP
	}
	return fmt.Sprintf("%s:%d", host, c.RemotePort)
}

// Bytes is the total in both directions.
func (c Connection) Bytes() uint64 { return c.BytesIn + c.BytesOut }

// Duration is the time between the first and the last packet.
func (c Connection) Duration() time.Duration { return c.Last.Sub(c.First) }

// Totals are overall counts, for a status bar.
type Totals struct {
	Apps        int
	Connections int
	Packets     int // all packets ever added
	Evicted     int // connections dropped to stay within Limits.MaxConns
}

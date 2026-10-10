package store

import (
	"sort"
	"time"

	"bubble-packet/internal/source/littlesnitch"
	"bubble-packet/internal/source/tshark"
)

// Limits bound how much the store remembers.
type Limits struct {
	MaxConns   int           // connections kept; the least recently active goes first
	MaxPackets int           // packets kept per connection
	KeepFirst  int           // of those, the first ones are never dropped, so handshakes survive
	UDPIdle    time.Duration // a UDP connection is idle after this long without a packet
}

// DefaultLimits are the values from the spec.
var DefaultLimits = Limits{MaxConns: 500, MaxPackets: 200, KeepFirst: 20, UDPIdle: 30 * time.Second}

// Store is the in-memory state. See the package comment.
type Store struct {
	limits Limits
	now    func() time.Time

	apps map[string]*app
	// addrApps answers "which apps use this remote address and port?".
	// It is the join between the two sources.
	addrApps map[addrKey]map[string]struct{}
	ipNames  map[string]string // remote address -> last host name seen for it

	conns   map[ConnKey]*conn
	packets int
	evicted int
}

type app struct {
	id, name          string
	bytesIn, bytesOut uint64
	connects, denies  int
	last              time.Time
	hosts             map[hostKey]*host
}

type hostKey struct {
	label    string // host name, or address when there is none
	port     uint16
	proto    uint8
	outbound bool
}

type host struct {
	hostname          string
	ips               map[string]struct{}
	bytesIn, bytesOut uint64
	connects, denies  int
	last              time.Time
}

type addrKey struct {
	ip    string
	port  uint16
	proto uint8
}

type conn struct {
	key                   ConnKey
	localIP, remoteIP     string
	localPort, remotePort uint16
	serverName            string
	protocol              string // highest-level protocol Wireshark named, e.g. "TLSv1.3"
	first, last           time.Time
	packets               int
	bytesIn, bytesOut     uint64

	// head holds the first packets and is never trimmed; tail holds the
	// most recent ones.
	head, tail []tshark.Packet

	// What the TCP flags have told us so far.
	midstream   bool // first packet seen was not a SYN
	sawSynAck   bool
	established bool
	finOut      bool
	finIn       bool
	rst         bool
}

// New returns an empty store with DefaultLimits.
func New() *Store { return NewWithLimits(DefaultLimits) }

// NewWithLimits returns an empty store. Zero fields take the default.
func NewWithLimits(l Limits) *Store {
	if l.MaxConns <= 0 {
		l.MaxConns = DefaultLimits.MaxConns
	}
	if l.MaxPackets <= 0 {
		l.MaxPackets = DefaultLimits.MaxPackets
	}
	if l.KeepFirst <= 0 || l.KeepFirst > l.MaxPackets {
		l.KeepFirst = min(DefaultLimits.KeepFirst, l.MaxPackets)
	}
	if l.UDPIdle <= 0 {
		l.UDPIdle = DefaultLimits.UDPIdle
	}
	return &Store{
		limits:   l,
		now:      time.Now,
		apps:     map[string]*app{},
		addrApps: map[addrKey]map[string]struct{}{},
		ipNames:  map[string]string{},
		conns:    map[ConnKey]*conn{},
	}
}

// SetClock replaces the clock used to decide whether a UDP connection is
// idle. Tests and replays use it.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// AddTraffic records one Little Snitch row.
func (s *Store) AddTraffic(st littlesnitch.Stat) {
	id := st.AppID()
	if id == "" {
		id = "unknown"
	}
	a := s.apps[id]
	if a == nil {
		a = &app{id: id, name: littlesnitch.AppName(id), hosts: map[hostKey]*host{}}
		s.apps[id] = a
	}
	a.bytesIn += st.BytesIn
	a.bytesOut += st.BytesOut
	a.connects += st.Connects
	a.denies += st.Denies
	a.last = later(a.last, st.Time)

	label := st.Hostname
	if label == "" {
		label = st.IP
	}
	hk := hostKey{label: label, port: st.Port, proto: st.Proto, outbound: st.Outbound}
	h := a.hosts[hk]
	if h == nil {
		h = &host{hostname: st.Hostname, ips: map[string]struct{}{}}
		a.hosts[hk] = h
	}
	h.ips[st.IP] = struct{}{}
	h.bytesIn += st.BytesIn
	h.bytesOut += st.BytesOut
	h.connects += st.Connects
	h.denies += st.Denies
	h.last = later(h.last, st.Time)

	if st.Hostname != "" {
		s.ipNames[st.IP] = st.Hostname
	}
	// Only outbound rows carry the remote port, which the join needs.
	if st.Outbound {
		ak := addrKey{ip: st.IP, port: st.Port, proto: st.Proto}
		if s.addrApps[ak] == nil {
			s.addrApps[ak] = map[string]struct{}{}
		}
		s.addrApps[ak][a.name] = struct{}{}
	}
}

// AddPacket records one packet, creating its connection when it is the first.
func (s *Store) AddPacket(p tshark.Packet) {
	s.packets++
	key := ConnKey{Proto: p.Proto, Stream: p.Stream}
	c := s.conns[key]
	if c == nil {
		c = &conn{key: key, first: p.Time}
		if p.Outbound {
			c.localIP, c.localPort, c.remoteIP, c.remotePort = p.SrcIP, p.SrcPort, p.DstIP, p.DstPort
		} else {
			c.localIP, c.localPort, c.remoteIP, c.remotePort = p.DstIP, p.DstPort, p.SrcIP, p.SrcPort
		}
		c.midstream = p.Proto == ProtoTCP && !p.Has(tshark.FlagSYN)
		s.conns[key] = c
		s.evict(key)
	}

	// Direction is judged against the connection, so every packet of a
	// connection agrees on which end is local.
	p.Outbound = p.SrcIP == c.localIP && p.SrcPort == c.localPort

	c.packets++
	c.last = later(c.last, p.Time)
	if p.Outbound {
		c.bytesOut += uint64(p.Len)
	} else {
		c.bytesIn += uint64(p.Len)
	}
	if p.ServerName != "" {
		c.serverName = p.ServerName
	}
	// Plain TCP packets (handshake, ACKs) say "TCP"; keep the more telling
	// name once a packet has revealed what runs on top.
	if p.Protocol != "" && p.Protocol != "TCP" && p.Protocol != "UDP" {
		c.protocol = p.Protocol
	}
	if p.Proto == ProtoTCP {
		c.observe(p)
	}
	s.keep(c, p)
}

// observe updates the TCP state from one packet's flags.
//
// Opening a connection takes three packets, the handshake:
//
//	client -> server  SYN       "I want to talk"
//	server -> client  SYN, ACK  "so do I, and I heard you"
//	client -> server  ACK       "I heard you too"
//
// Closing takes a FIN from each side. A RST from either side ends it at once.
func (c *conn) observe(p tshark.Packet) {
	syn, ack := p.Has(tshark.FlagSYN), p.Has(tshark.FlagACK)
	switch {
	case syn && ack:
		c.sawSynAck = true
	case ack && !syn && c.sawSynAck:
		c.established = true
	}
	if p.Has(tshark.FlagFIN) {
		if p.Outbound {
			c.finOut = true
		} else {
			c.finIn = true
		}
	}
	if p.Has(tshark.FlagRST) {
		c.rst = true
	}
}

func (c *conn) state(now time.Time, udpIdle time.Duration) State {
	if c.key.Proto != ProtoTCP {
		if now.Sub(c.last) < udpIdle {
			return StateActive
		}
		return StateIdle
	}
	switch {
	case c.rst:
		return StateReset
	case c.finOut && c.finIn:
		return StateClosed
	case c.finOut || c.finIn:
		return StateClosing
	case c.midstream:
		return StateMidstream
	case c.established:
		return StateOpen
	}
	return StateOpening
}

// keep stores the packet within the per-connection limit.
func (s *Store) keep(c *conn, p tshark.Packet) {
	if len(c.head) < s.limits.KeepFirst {
		c.head = append(c.head, p)
		return
	}
	room := s.limits.MaxPackets - s.limits.KeepFirst
	if room == 0 {
		return
	}
	if len(c.tail) < room {
		c.tail = append(c.tail, p)
		return
	}
	copy(c.tail, c.tail[1:])
	c.tail[len(c.tail)-1] = p
}

// evict drops the least recently active connection when there are too many.
// The connection just created is never the one dropped.
func (s *Store) evict(justAdded ConnKey) {
	for len(s.conns) > s.limits.MaxConns {
		var oldest *conn
		for k, c := range s.conns {
			if k == justAdded {
				continue
			}
			if oldest == nil || c.last.Before(oldest.last) {
				oldest = c
			}
		}
		if oldest == nil {
			return
		}
		delete(s.conns, oldest.key)
		s.evicted++
	}
}

// Apps returns every app seen, busiest first.
func (s *Store) Apps() []AppRow {
	rows := make([]AppRow, 0, len(s.apps))
	for _, a := range s.apps {
		rows = append(rows, AppRow{
			ID: a.id, Name: a.name,
			BytesIn: a.bytesIn, BytesOut: a.bytesOut,
			Connects: a.connects, Denies: a.denies,
			Hosts: len(a.hosts), LastSeen: a.last,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes() != rows[j].Bytes() {
			return rows[i].Bytes() > rows[j].Bytes()
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

// Hosts returns the hosts one app talks to, busiest first.
// appID is the ID field of an AppRow.
func (s *Store) Hosts(appID string) []HostRow {
	a := s.apps[appID]
	if a == nil {
		return nil
	}
	rows := make([]HostRow, 0, len(a.hosts))
	for k, h := range a.hosts {
		ips := make([]string, 0, len(h.ips))
		for ip := range h.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		rows = append(rows, HostRow{
			Hostname: h.hostname, IPs: ips,
			Port: k.port, Proto: k.proto, Outbound: k.outbound,
			BytesIn: h.bytesIn, BytesOut: h.bytesOut,
			Connects: h.connects, Denies: h.denies, LastSeen: h.last,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		x, y := rows[i], rows[j]
		if x.Bytes() != y.Bytes() {
			return x.Bytes() > y.Bytes()
		}
		if x.Label() != y.Label() {
			return x.Label() < y.Label()
		}
		if x.Port != y.Port {
			return x.Port < y.Port
		}
		if x.Proto != y.Proto {
			return x.Proto < y.Proto
		}
		return x.Outbound && !y.Outbound
	})
	return rows
}

// Connections returns every connection in memory, newest first.
func (s *Store) Connections() []Connection {
	return s.connections(func(*conn) bool { return true })
}

// ConnectionsFor returns the connections to one host, newest first.
//
// The match is by address, port and protocol only. tshark does not know
// which app owns a packet, so when two apps talk to the same server this
// returns the connections of both.
func (s *Store) ConnectionsFor(h HostRow) []Connection {
	ips := make(map[string]bool, len(h.IPs))
	for _, ip := range h.IPs {
		ips[ip] = true
	}
	return s.connections(func(c *conn) bool {
		if c.key.Proto != h.Proto || !ips[c.remoteIP] {
			return false
		}
		if h.Outbound {
			return c.remotePort == h.Port
		}
		return c.localPort == h.Port
	})
}

func (s *Store) connections(want func(*conn) bool) []Connection {
	now := s.now()
	var rows []Connection
	for _, c := range s.conns {
		if want(c) {
			rows = append(rows, s.snapshot(c, now))
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		x, y := rows[i], rows[j]
		if !x.First.Equal(y.First) {
			return x.First.After(y.First)
		}
		if x.Key.Proto != y.Key.Proto {
			return x.Key.Proto < y.Key.Proto
		}
		return x.Key.Stream > y.Key.Stream
	})
	return rows
}

// Connection returns one connection, and false when it is not in memory
// (never seen, or evicted).
func (s *Store) Connection(key ConnKey) (Connection, bool) {
	c := s.conns[key]
	if c == nil {
		return Connection{}, false
	}
	return s.snapshot(c, s.now()), true
}

func (s *Store) snapshot(c *conn, now time.Time) Connection {
	hostname := c.serverName
	if hostname == "" {
		hostname = s.ipNames[c.remoteIP]
	}
	var apps []string
	for name := range s.addrApps[addrKey{ip: c.remoteIP, port: c.remotePort, proto: c.key.Proto}] {
		apps = append(apps, name)
	}
	sort.Strings(apps)
	protocol := c.protocol
	if protocol == "" {
		protocol = ProtoName(c.key.Proto)
	}
	return Connection{
		Key:      c.key,
		Protocol: protocol,
		LocalIP:  c.localIP, LocalPort: c.localPort,
		RemoteIP: c.remoteIP, RemotePort: c.remotePort,
		ServerName: c.serverName, Hostname: hostname, Apps: apps,
		First: c.first, Last: c.last,
		Packets: c.packets, Kept: len(c.head) + len(c.tail),
		BytesIn: c.bytesIn, BytesOut: c.bytesOut,
		State: c.state(now, s.limits.UDPIdle),
	}
}

// Packets returns the packets kept for a connection, oldest first.
//
// When a connection had more packets than the limit, the first ones and the
// latest ones are returned and the middle is missing: compare the Connection's
// Packets and Kept fields to know.
func (s *Store) Packets(key ConnKey) []tshark.Packet {
	c := s.conns[key]
	if c == nil {
		return nil
	}
	out := make([]tshark.Packet, 0, len(c.head)+len(c.tail))
	out = append(out, c.head...)
	return append(out, c.tail...)
}

// Totals returns overall counts.
func (s *Store) Totals() Totals {
	return Totals{Apps: len(s.apps), Connections: len(s.conns), Packets: s.packets, Evicted: s.evicted}
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

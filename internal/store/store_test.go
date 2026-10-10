package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"bubble-packet/internal/source/littlesnitch"
	"bubble-packet/internal/source/tshark"
)

const (
	me     = "192.168.1.23"
	server = "140.82.121.4"
)

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func stat(app, host, ip string, port uint16, in, out uint64) littlesnitch.Stat {
	return littlesnitch.Stat{
		Time: t0, Outbound: true, IP: ip, Hostname: host, Proto: ProtoTCP, Port: port,
		Connects: 1, BytesIn: in, BytesOut: out, Executable: app,
	}
}

// pkt builds a packet on a connection between me:50000 and server:443.
func pkt(stream int, outbound bool, flags uint16, sec int) tshark.Packet {
	p := tshark.Packet{
		Time: t0.Add(time.Duration(sec) * time.Second), Proto: ProtoTCP, Stream: stream,
		Flags: flags, Len: 100, Outbound: outbound,
	}
	if outbound {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = me, 50000, server, 443
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = server, 443, me, 50000
	}
	return p
}

func stateOf(t *testing.T, s *Store, stream int) State {
	t.Helper()
	c, ok := s.Connection(ConnKey{ProtoTCP, stream})
	if !ok {
		t.Fatalf("connection %d missing", stream)
	}
	return c.State
}

func TestAppsAndHosts(t *testing.T) {
	s := New()
	s.AddTraffic(stat("/Applications/Safari.app", "github.com", "140.82.121.4", 443, 1000, 100))
	s.AddTraffic(stat("/Applications/Safari.app", "github.com", "140.82.121.3", 443, 500, 50))
	s.AddTraffic(stat("/Applications/Safari.app", "", "1.1.1.1", 853, 10, 10))
	s.AddTraffic(stat("/usr/bin/curl", "example.com", "93.184.215.14", 443, 5000, 5))
	denied := stat("/Applications/Safari.app", "ads.example.net", "198.51.100.7", 443, 0, 0)
	denied.Connects, denied.Denies = 0, 3
	s.AddTraffic(denied)

	apps := s.Apps()
	if len(apps) != 2 || apps[0].Name != "curl" || apps[1].Name != "Safari" {
		t.Fatalf("apps not sorted by bytes: %+v", apps)
	}
	safari := apps[1]
	if safari.BytesIn != 1510 || safari.BytesOut != 160 || safari.Connects != 3 || safari.Denies != 3 || safari.Hosts != 3 {
		t.Errorf("Safari totals wrong: %+v", safari)
	}

	hosts := s.Hosts(safari.ID)
	if len(hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(hosts))
	}
	gh := hosts[0]
	if gh.Label() != "github.com" || len(gh.IPs) != 2 || gh.IPs[0] != "140.82.121.3" || gh.Bytes() != 1650 {
		t.Errorf("github row should merge both addresses: %+v", gh)
	}
	if hosts[1].Label() != "1.1.1.1" || hosts[1].Hostname != "" {
		t.Errorf("a host without a name is labelled by address: %+v", hosts[1])
	}
	if hosts[2].Denies != 3 {
		t.Errorf("denies not carried: %+v", hosts[2])
	}
	if s.Hosts("nope") != nil {
		t.Errorf("unknown app should have no hosts")
	}
}

func TestHandshakeAndClose(t *testing.T) {
	s := New()
	steps := []struct {
		p    tshark.Packet
		want State
	}{
		{pkt(1, true, tshark.FlagSYN, 0), StateOpening},
		{pkt(1, false, tshark.FlagSYN|tshark.FlagACK, 1), StateOpening},
		{pkt(1, true, tshark.FlagACK, 2), StateOpen},
		{pkt(1, true, tshark.FlagPSH|tshark.FlagACK, 3), StateOpen},
		{pkt(1, true, tshark.FlagFIN|tshark.FlagACK, 4), StateClosing},
		{pkt(1, false, tshark.FlagFIN|tshark.FlagACK, 5), StateClosed},
		{pkt(1, true, tshark.FlagACK, 6), StateClosed},
	}
	for i, st := range steps {
		s.AddPacket(st.p)
		if got := stateOf(t, s, 1); got != st.want {
			t.Fatalf("after packet %d: state %v, want %v", i, got, st.want)
		}
	}

	c, _ := s.Connection(ConnKey{ProtoTCP, 1})
	if c.LocalIP != me || c.LocalPort != 50000 || c.RemoteIP != server || c.RemotePort != 443 {
		t.Errorf("endpoints wrong: %+v", c)
	}
	if c.Packets != 7 || c.Kept != 7 || c.BytesOut != 500 || c.BytesIn != 200 {
		t.Errorf("counts wrong: %+v", c)
	}
	if c.Duration() != 6*time.Second || c.Label() != server+":443" {
		t.Errorf("duration %v label %q", c.Duration(), c.Label())
	}
}

func TestResetMidstreamAndLateStart(t *testing.T) {
	s := New()

	s.AddPacket(pkt(1, true, tshark.FlagSYN, 0))
	s.AddPacket(pkt(1, false, tshark.FlagRST|tshark.FlagACK, 1))
	if got := stateOf(t, s, 1); got != StateReset {
		t.Errorf("refused connection: %v", got)
	}

	s.AddPacket(pkt(2, false, tshark.FlagPSH|tshark.FlagACK, 0))
	s.AddPacket(pkt(2, true, tshark.FlagACK, 1))
	if got := stateOf(t, s, 2); got != StateMidstream {
		t.Errorf("no SYN seen: %v", got)
	}
	s.AddPacket(pkt(2, true, tshark.FlagFIN|tshark.FlagACK, 2))
	if got := stateOf(t, s, 2); got != StateClosing {
		t.Errorf("midstream then FIN: %v", got)
	}

	// The capture began between the SYN and the SYN-ACK.
	s.AddPacket(pkt(3, false, tshark.FlagSYN|tshark.FlagACK, 0))
	s.AddPacket(pkt(3, true, tshark.FlagACK, 1))
	if got := stateOf(t, s, 3); got != StateOpen {
		t.Errorf("SYN-ACK first: %v", got)
	}
	if c, _ := s.Connection(ConnKey{ProtoTCP, 3}); c.LocalIP != me || c.RemotePort != 443 {
		t.Errorf("inbound first packet: endpoints wrong: %+v", c)
	}
}

// A packet whose direction was guessed wrong must not flip the connection.
func TestDirectionFollowsTheConnection(t *testing.T) {
	s := New()
	s.AddPacket(pkt(1, true, tshark.FlagSYN, 0))
	reply := pkt(1, false, tshark.FlagSYN|tshark.FlagACK, 1)
	reply.Outbound = true // wrong on purpose
	s.AddPacket(reply)

	c, _ := s.Connection(ConnKey{ProtoTCP, 1})
	if c.BytesIn != 100 || c.BytesOut != 100 {
		t.Errorf("bytes in/out = %d/%d", c.BytesIn, c.BytesOut)
	}
	if ps := s.Packets(c.Key); ps[1].Outbound {
		t.Errorf("stored packet keeps the wrong direction")
	}
}

func TestJoin(t *testing.T) {
	s := New()
	s.AddPacket(pkt(1, true, tshark.FlagSYN, 0))

	c, _ := s.Connection(ConnKey{ProtoTCP, 1})
	if len(c.Apps) != 0 || c.Hostname != "" {
		t.Fatalf("nothing known yet, got %+v", c)
	}

	// Little Snitch reports later; the connection picks it up.
	s.AddTraffic(stat("/Applications/Safari.app", "github.com", server, 443, 1, 1))
	c, _ = s.Connection(ConnKey{ProtoTCP, 1})
	if len(c.Apps) != 1 || c.Apps[0] != "Safari" || c.Hostname != "github.com" || c.Label() != "github.com:443" {
		t.Fatalf("after Little Snitch row: %+v", c)
	}

	// Two apps, one server: both are listed.
	s.AddTraffic(stat("/Applications/Slack.app", "github.com", server, 443, 1, 1))
	c, _ = s.Connection(ConnKey{ProtoTCP, 1})
	if strings.Join(c.Apps, ",") != "Safari,Slack" {
		t.Errorf("apps = %v", c.Apps)
	}

	// Same address, other port or protocol: no match.
	s.AddTraffic(stat("/usr/bin/curl", "", server, 80, 1, 1))
	udp := stat("/usr/bin/dig", "", server, 443, 1, 1)
	udp.Proto = ProtoUDP
	s.AddTraffic(udp)
	c, _ = s.Connection(ConnKey{ProtoTCP, 1})
	if len(c.Apps) != 2 {
		t.Errorf("join must use port and protocol: %v", c.Apps)
	}

	if c.Protocol != "TCP" {
		t.Errorf("protocol before any TLS packet = %q", c.Protocol)
	}

	// The name from TLS wins over the Little Snitch name.
	hello := pkt(1, true, tshark.FlagPSH|tshark.FlagACK, 1)
	hello.ServerName = "api.github.com"
	hello.Protocol = "TLSv1.3"
	s.AddPacket(hello)
	ackOnly := pkt(1, false, tshark.FlagACK, 2)
	ackOnly.Protocol = "TCP"
	s.AddPacket(ackOnly)
	c, _ = s.Connection(ConnKey{ProtoTCP, 1})
	if c.ServerName != "api.github.com" || c.Hostname != "api.github.com" {
		t.Errorf("server name: %+v", c)
	}
	if c.Protocol != "TLSv1.3" {
		t.Errorf("a later plain TCP packet must not hide the protocol: %q", c.Protocol)
	}
}

func TestConnectionsFor(t *testing.T) {
	s := New()
	s.AddTraffic(stat("/Applications/Safari.app", "github.com", server, 443, 1, 1))
	s.AddTraffic(stat("/Applications/Safari.app", "github.com", "140.82.121.3", 443, 1, 1))
	s.AddTraffic(littlesnitch.Stat{Time: t0, Outbound: false, IP: "192.168.1.40", Proto: ProtoTCP, Port: 50000, Executable: "/usr/libexec/rapportd"})

	s.AddPacket(pkt(1, true, tshark.FlagSYN, 0))
	other := pkt(2, true, tshark.FlagSYN, 5)
	other.DstIP = "140.82.121.3"
	s.AddPacket(other)
	elsewhere := pkt(3, true, tshark.FlagSYN, 6)
	elsewhere.DstIP = "9.9.9.9"
	s.AddPacket(elsewhere)
	inbound := pkt(4, false, tshark.FlagSYN, 7)
	inbound.SrcIP, inbound.SrcPort = "192.168.1.40", 61000
	s.AddPacket(inbound)

	gh := s.Hosts("/Applications/Safari.app")[0]
	got := s.ConnectionsFor(gh)
	if len(got) != 2 || got[0].Key.Stream != 2 || got[1].Key.Stream != 1 {
		t.Fatalf("want streams 2 then 1 (newest first), got %+v", got)
	}

	in := s.Hosts("/usr/libexec/rapportd")[0]
	if in.Outbound {
		t.Fatalf("expected an inbound host row")
	}
	if got := s.ConnectionsFor(in); len(got) != 1 || got[0].Key.Stream != 4 {
		t.Errorf("inbound host matches on the local port: %+v", got)
	}

	if all := s.Connections(); len(all) != 4 || all[0].Key.Stream != 4 {
		t.Errorf("Connections: %d rows, first %+v", len(all), all[0])
	}
}

func TestPacketLimitKeepsTheHandshake(t *testing.T) {
	s := NewWithLimits(Limits{MaxPackets: 10, KeepFirst: 3})
	for i := 0; i < 25; i++ {
		p := pkt(1, i%2 == 0, tshark.FlagACK, i)
		p.Info = fmt.Sprint(i)
		s.AddPacket(p)
	}
	c, _ := s.Connection(ConnKey{ProtoTCP, 1})
	if c.Packets != 25 || c.Kept != 10 || c.Bytes() != 2500 {
		t.Fatalf("packets=%d kept=%d bytes=%d", c.Packets, c.Kept, c.Bytes())
	}
	var got []string
	for _, p := range s.Packets(c.Key) {
		got = append(got, p.Info)
	}
	if want := "0 1 2 18 19 20 21 22 23 24"; strings.Join(got, " ") != want {
		t.Errorf("kept %v, want %s", got, want)
	}
	if s.Packets(ConnKey{ProtoTCP, 99}) != nil {
		t.Errorf("unknown connection should have no packets")
	}
}

func TestEvictsLeastRecentlyActive(t *testing.T) {
	s := NewWithLimits(Limits{MaxConns: 3})
	s.AddPacket(pkt(1, true, tshark.FlagSYN, 0))
	s.AddPacket(pkt(2, true, tshark.FlagSYN, 1))
	s.AddPacket(pkt(3, true, tshark.FlagSYN, 2))
	s.AddPacket(pkt(1, true, tshark.FlagACK, 3)) // 1 is active again; 2 is now the oldest
	s.AddPacket(pkt(4, true, tshark.FlagSYN, 4))

	if _, ok := s.Connection(ConnKey{ProtoTCP, 2}); ok {
		t.Errorf("stream 2 should have been evicted")
	}
	for _, id := range []int{1, 3, 4} {
		if _, ok := s.Connection(ConnKey{ProtoTCP, id}); !ok {
			t.Errorf("stream %d should still be there", id)
		}
	}
	if tot := s.Totals(); tot.Connections != 3 || tot.Evicted != 1 || tot.Packets != 5 {
		t.Errorf("totals = %+v", tot)
	}
}

func TestUDPActiveThenIdle(t *testing.T) {
	s := New()
	now := t0
	s.SetClock(func() time.Time { return now })

	q := tshark.Packet{Time: t0, Proto: ProtoUDP, Stream: 1, SrcIP: me, SrcPort: 61000, DstIP: "192.168.1.1", DstPort: 53, Len: 70, Outbound: true}
	s.AddPacket(q)
	// TCP and UDP stream numbers do not collide.
	s.AddPacket(pkt(1, true, tshark.FlagSYN, 0))

	c, _ := s.Connection(ConnKey{ProtoUDP, 1})
	if c.State != StateActive || c.RemotePort != 53 {
		t.Fatalf("fresh UDP: %+v", c)
	}
	now = t0.Add(31 * time.Second)
	if c, _ = s.Connection(ConnKey{ProtoUDP, 1}); c.State != StateIdle {
		t.Errorf("after 31 s: %v", c.State)
	}
	if got := stateOf(t, s, 1); got != StateOpening {
		t.Errorf("TCP stream 1 is separate: %v", got)
	}
}

func TestDemo(t *testing.T) {
	s := Demo()
	apps := s.Apps()
	if len(apps) < 6 {
		t.Fatalf("demo has %d apps", len(apps))
	}

	seen := map[State]bool{}
	var trimmed, shared, unmatched bool
	for _, c := range s.Connections() {
		seen[c.State] = true
		trimmed = trimmed || c.Kept < c.Packets
		shared = shared || len(c.Apps) > 1
		unmatched = unmatched || len(c.Apps) == 0
		if len(s.Packets(c.Key)) != c.Kept {
			t.Errorf("%s: Packets returned %d, Kept says %d", c.Label(), len(s.Packets(c.Key)), c.Kept)
		}
	}
	for _, st := range []State{StateOpening, StateOpen, StateMidstream, StateClosed, StateReset, StateActive, StateIdle} {
		if !seen[st] {
			t.Errorf("demo has no %v connection", st)
		}
	}
	if !trimmed || !shared || !unmatched {
		t.Errorf("demo cases missing: trimmed=%v shared=%v unmatched=%v", trimmed, shared, unmatched)
	}

	// Every host of every app can be drilled into without surprises.
	var withConns int
	for _, a := range apps {
		hosts := s.Hosts(a.ID)
		if len(hosts) != a.Hosts {
			t.Errorf("%s: Hosts=%d but %d rows", a.Name, a.Hosts, len(hosts))
		}
		for _, h := range hosts {
			if len(s.ConnectionsFor(h)) > 0 {
				withConns++
			}
		}
	}
	if withConns < 6 {
		t.Errorf("only %d hosts have connections", withConns)
	}

	bytesOf := func(name string) uint64 {
		for _, a := range s.Apps() {
			if a.Name == name {
				return a.Bytes()
			}
		}
		t.Fatalf("no app named %s", name)
		return 0
	}
	before := s.Totals()
	safari := bytesOf("Safari")
	for n := 1; n <= 12; n++ {
		DemoTick(s, n)
	}
	after := s.Totals()
	if after.Packets <= before.Packets || after.Connections <= before.Connections {
		t.Errorf("DemoTick added nothing: %+v -> %+v", before, after)
	}
	if bytesOf("Safari") <= safari {
		t.Errorf("DemoTick did not grow Safari")
	}
}

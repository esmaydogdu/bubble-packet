package store

import (
	"fmt"
	"time"

	"bubble-packet/internal/source/littlesnitch"
	"bubble-packet/internal/source/tshark"
)

// Demo returns a store filled with made-up traffic, for building the UI
// without root, Little Snitch or tshark.
//
// The data goes through AddTraffic and AddPacket like real data, so
// everything the read methods return has the shape of the real thing. It
// contains one example of each case the UI has to draw:
//
//   - TCP connections in every state: opening, open, midstream, closed, reset
//   - UDP connections, one active (QUIC) and one idle (DNS)
//   - a full TCP and TLS handshake to read packet by packet (github.com)
//   - a connection with more packets than are kept (Packets > Kept)
//   - one server used by two apps (cdn.jsdelivr.net: Safari and Slack)
//   - a connection no app has been matched to yet
//   - a host name with two addresses, a host with no name, an inbound host
//   - an app with blocked connections, and one using ICMP
func Demo() *Store {
	s := New()
	t0 := time.Now().Add(-2 * time.Minute)
	at := func(sec float64) time.Time { return t0.Add(time.Duration(sec * float64(time.Second))) }

	stat := func(sec float64, app, host, ip string, proto uint8, port uint16, connects, denies int, in, out uint64) {
		s.AddTraffic(littlesnitch.Stat{
			Time: at(sec), Outbound: true, UID: 501, IP: ip, Hostname: host, Proto: proto, Port: port,
			Connects: connects, Denies: denies, BytesIn: in, BytesOut: out, Executable: app,
		})
	}

	stat(1, demoSafari, "github.com", demoGitHubIP, ProtoTCP, 443, 2, 0, 310_000, 42_000)
	stat(2, demoSafari, "github.com", "140.82.121.3", ProtoTCP, 443, 1, 0, 24_000, 3_100)
	stat(3, demoSafari, "fonts.gstatic.com", demoQUICIP, ProtoUDP, 443, 1, 0, 80_000, 6_000)
	stat(4, demoSafari, "cdn.jsdelivr.net", demoCDNIP, ProtoTCP, 443, 1, 0, 120_000, 3_000)
	stat(5, demoSlack, "slack.com", demoSlackIP, ProtoTCP, 443, 3, 0, 64_000, 21_000)
	stat(6, demoSlack, "cdn.jsdelivr.net", demoCDNIP, ProtoTCP, 443, 1, 0, 9_000, 1_200)
	stat(7, "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd",
		"43-courier.push.apple.com", "17.188.185.137", ProtoTCP, 5223, 1, 0, 4_806, 9_190)
	stat(8, demoDNS, "", demoRouterIP, ProtoUDP, 53, 6, 0, 1_420, 610)
	stat(9, "/usr/bin/curl", "example.com", "93.184.215.14", ProtoTCP, 443, 1, 0, 0, 640)
	stat(10, "/Applications/Spotify.app", "analytics.example.net", "198.51.100.7", ProtoTCP, 443, 0, 3, 0, 0)
	stat(11, "/Applications/Spotify.app", "audio.example.net", "198.51.100.20", ProtoTCP, 443, 1, 0, 2_400_000, 18_000)
	stat(12, "/opt/homebrew/sbin/mtr-packet", "", "13.107.5.93", ProtoICMP, 0, 1, 0, 0, 0)
	s.AddTraffic(littlesnitch.Stat{ // someone on the local network connecting in
		Time: at(13), Outbound: false, IP: "192.168.1.40", Proto: ProtoTCP, Port: 49152,
		Connects: 1, BytesIn: 2_048, BytesOut: 512, Executable: "/usr/libexec/rapportd",
	})

	// Closed: the whole life of a connection, handshake to goodbye.
	c := demoDial(s, ProtoTCP, 0, 52311, demoGitHubIP, 443, at(20))
	c.handshake()
	c.tls("github.com")
	for i := 0; i < 6; i++ {
		c.out(40, tshark.FlagPSH|tshark.FlagACK, 420, "TLSv1.3", "Application Data")
		c.in(35, tshark.FlagPSH|tshark.FlagACK, 1440, "TLSv1.3", "Application Data")
	}
	c.out(900, tshark.FlagFIN|tshark.FlagACK, 66, "TCP", "")
	c.in(22, tshark.FlagFIN|tshark.FlagACK, 66, "TCP", "")
	c.out(1, tshark.FlagACK, 66, "TCP", "")

	// Open, and long enough that the middle of it is no longer kept.
	c = demoDial(s, ProtoTCP, demoOpenStream, demoOpenPort, demoGitHubIP, 443, at(40))
	c.handshake()
	c.tls("github.com")
	for i := 0; i < 150; i++ {
		c.out(60, tshark.FlagPSH|tshark.FlagACK, 380, "TLSv1.3", "Application Data")
		c.in(45, tshark.FlagPSH|tshark.FlagACK, 1440, "TLSv1.3", "Application Data")
	}

	// Midstream: it was already running when the capture started.
	c = demoDial(s, ProtoTCP, 2, 49731, "17.188.185.137", 5223, at(21))
	for i := 0; i < 4; i++ {
		c.in(9000, tshark.FlagPSH|tshark.FlagACK, 131, "TLSv1.2", "Application Data")
		c.out(18, tshark.FlagACK, 66, "TCP", "")
	}

	// Reset: the server hung up in the middle of the TLS handshake.
	c = demoDial(s, ProtoTCP, 3, 52340, "93.184.215.14", 443, at(55))
	c.handshake()
	c.hello("example.com")
	c.in(140, tshark.FlagRST|tshark.FlagACK, 60, "TCP", "")

	// One server, two apps: the app column shows both.
	c = demoDial(s, ProtoTCP, 4, 52355, demoCDNIP, 443, at(60))
	c.handshake()
	c.tls("cdn.jsdelivr.net")
	c.in(30, tshark.FlagPSH|tshark.FlagACK, 1440, "TLSv1.3", "Application Data")

	// Opening: a SYN that has not been answered, then sent again.
	c = demoDial(s, ProtoTCP, 5, 52360, demoSlackIP, 443, at(110))
	c.out(0, tshark.FlagSYN, 78, "TCP", "")
	c.out(1000, tshark.FlagSYN, 78, "TCP", "[TCP Retransmission] ")

	// No app: Little Snitch has not reported this address.
	c = demoDial(s, ProtoTCP, 6, 52371, "203.0.113.9", 8443, at(70))
	c.out(0, tshark.FlagPSH|tshark.FlagACK, 210, "TCP", "")
	c.in(48, tshark.FlagACK, 66, "TCP", "")

	// Idle UDP: a DNS question and its answer, two minutes ago.
	c = demoDial(s, ProtoUDP, 0, 61012, demoRouterIP, 53, at(19))
	c.out(0, 0, 70, "DNS", "Standard query 0x1a2b A github.com")
	c.in(11, 0, 86, "DNS", "Standard query response 0x1a2b A github.com A "+demoGitHubIP)

	// Active UDP: QUIC, the protocol HTTP/3 runs on. No SYN, no FIN.
	c = demoDial(s, ProtoUDP, demoQUICStream, demoQUICPort, demoQUICIP, 443, at(100))
	c.out(0, 0, 1292, "QUIC", "Initial, DCID=4f2a9c11, PKN: 0, CRYPTO")
	c.in(24, 0, 1292, "QUIC", "Initial, SCID=8be0, PKN: 0, ACK, CRYPTO")
	c.in(2, 0, 1292, "QUIC", "Handshake, SCID=8be0, PKN: 0, CRYPTO")
	c.out(6, 0, 122, "QUIC", "Handshake, DCID=8be0, PKN: 0, ACK, CRYPTO")
	for i := 0; i < 5; i++ {
		c.in(4000, 0, 1292, "QUIC", "Protected Payload (KP0)")
		c.out(3, 0, 85, "QUIC", "Protected Payload (KP0)")
	}
	return s
}

// DemoTick adds a little more made-up traffic to a store from Demo, so the
// live-update path of the UI can be built and watched. Call it on a timer
// with n = 1, 2, 3, ...
//
// Every call the open github.com connection and the QUIC connection carry
// data. Every fourth call there is a DNS lookup, and every sixth call Slack
// opens a new connection.
func DemoTick(s *Store, n int) {
	now := time.Now()
	grow := uint64(18_000 + (n%5)*4_000)
	s.AddTraffic(littlesnitch.Stat{
		Time: now, Outbound: true, UID: 501, IP: demoGitHubIP, Hostname: "github.com",
		Proto: ProtoTCP, Port: 443, BytesIn: grow, BytesOut: 1_500, Executable: demoSafari,
	})

	c := demoDial(s, ProtoTCP, demoOpenStream, demoOpenPort, demoGitHubIP, 443, now)
	c.out(0, tshark.FlagPSH|tshark.FlagACK, 380, "TLSv1.3", "Application Data")
	c.in(30, tshark.FlagPSH|tshark.FlagACK, 1440, "TLSv1.3", "Application Data")

	c = demoDial(s, ProtoUDP, demoQUICStream, demoQUICPort, demoQUICIP, 443, now)
	c.in(0, 0, 1292, "QUIC", "Protected Payload (KP0)")

	if n%4 == 0 {
		s.AddTraffic(littlesnitch.Stat{
			Time: now, Outbound: true, UID: 65, IP: demoRouterIP, Proto: ProtoUDP, Port: 53,
			Connects: 1, BytesIn: 86, BytesOut: 70, Executable: demoDNS,
		})
		c = demoDial(s, ProtoUDP, 1000+n, uint16(61100+n%1000), demoRouterIP, 53, now)
		c.out(0, 0, 70, "DNS", "Standard query 0x2c3d A slack.com")
		c.in(9, 0, 86, "DNS", "Standard query response 0x2c3d A slack.com A "+demoSlackIP)
	}
	if n%6 == 0 {
		s.AddTraffic(littlesnitch.Stat{
			Time: now, Outbound: true, UID: 501, IP: demoSlackIP, Hostname: "slack.com",
			Proto: ProtoTCP, Port: 443, Connects: 1, BytesIn: 5_200, BytesOut: 900, Executable: demoSlack,
		})
		c = demoDial(s, ProtoTCP, 1000+n, uint16(53000+n%1000), demoSlackIP, 443, now)
		c.handshake()
		c.tls("slack.com")
	}
}

const (
	demoLocalIP  = "192.168.1.23"
	demoRouterIP = "192.168.1.1"
	demoGitHubIP = "140.82.121.4"
	demoCDNIP    = "151.101.1.229"
	demoSlackIP  = "3.65.102.105"
	demoQUICIP   = "142.250.179.163"

	demoSafari = "/Applications/Safari.app"
	demoSlack  = "/Applications/Slack.app"
	demoDNS    = "/usr/sbin/mDNSResponder"

	demoOpenStream, demoOpenPort = 1, 52320
	demoQUICStream, demoQUICPort = 1, 61020
)

// demoConn writes the packets of one made-up connection.
type demoConn struct {
	s          *Store
	proto      uint8
	stream     int
	localPort  uint16
	remoteIP   string
	remotePort uint16
	t          time.Time
}

func demoDial(s *Store, proto uint8, stream int, localPort uint16, remoteIP string, remotePort uint16, start time.Time) *demoConn {
	return &demoConn{s: s, proto: proto, stream: stream, localPort: localPort, remoteIP: remoteIP, remotePort: remotePort, t: start}
}

// out and in add one packet, gapMs milliseconds after the previous one.
// For TCP, info is prefixed the way Wireshark writes it: "52311 → 443 [SYN]".
func (c *demoConn) out(gapMs int, flags uint16, size int, protocol, info string) {
	c.add(true, gapMs, flags, size, protocol, info, "")
}

func (c *demoConn) in(gapMs int, flags uint16, size int, protocol, info string) {
	c.add(false, gapMs, flags, size, protocol, info, "")
}

func (c *demoConn) add(outbound bool, gapMs int, flags uint16, size int, protocol, info, serverName string) {
	c.t = c.t.Add(time.Duration(gapMs) * time.Millisecond)
	p := tshark.Packet{
		Time: c.t, Proto: c.proto, Stream: c.stream, Flags: flags, Len: size,
		Protocol: protocol, Info: info, ServerName: serverName, Outbound: outbound,
	}
	if outbound {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = demoLocalIP, c.localPort, c.remoteIP, c.remotePort
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = c.remoteIP, c.remotePort, demoLocalIP, c.localPort
	}
	if protocol == "TCP" {
		p.Info = fmt.Sprintf("%s%d → %d [%s] Len=0", info, p.SrcPort, p.DstPort, p.FlagString())
	}
	c.s.AddPacket(p)
}

// handshake adds the three packets that open a TCP connection.
func (c *demoConn) handshake() {
	c.out(0, tshark.FlagSYN, 78, "TCP", "")
	c.in(21, tshark.FlagSYN|tshark.FlagACK, 74, "TCP", "")
	c.out(1, tshark.FlagACK, 66, "TCP", "")
}

// hello adds the TLS Client Hello, the packet that carries the server name
// in the clear.
func (c *demoConn) hello(name string) {
	c.add(true, 2, tshark.FlagPSH|tshark.FlagACK, 583, "TLSv1.3", "Client Hello (SNI="+name+")", name)
}

// tls adds the TLS handshake. After it, everything is encrypted and
// Wireshark can only say "Application Data".
func (c *demoConn) tls(name string) {
	c.hello(name)
	c.in(24, tshark.FlagACK, 66, "TCP", "")
	c.in(3, tshark.FlagPSH|tshark.FlagACK, 1440, "TLSv1.3", "Server Hello, Change Cipher Spec, Application Data")
	c.out(4, tshark.FlagPSH|tshark.FlagACK, 146, "TLSv1.3", "Change Cipher Spec, Application Data")
}

package tshark

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"bubble-packet/internal/source"
)

// Fields are the tshark fields we ask for, in output order. tshark prints
// one line per packet with these values separated by tabs.
var Fields = []string{
	"frame.time_epoch",
	"ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
	"tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
	"tcp.stream", "udp.stream",
	"tcp.flags", "frame.len",
	"_ws.col.protocol", "_ws.col.info",
	"tls.handshake.extensions_server_name",
}

// The position of each field in a line. Must match Fields.
const (
	fTime = iota
	fSrc4
	fSrc6
	fDst4
	fDst6
	fTCPSrcPort
	fUDPSrcPort
	fTCPDstPort
	fUDPDstPort
	fTCPStream
	fUDPStream
	fFlags
	fLen
	fProtocol
	fInfo
	fServerName
)

// ParseLine converts one line of tshark output into a Packet.
func ParseLine(line string, local Local) (Packet, error) {
	f := strings.Split(line, "\t")
	if len(f) != len(Fields) {
		return Packet{}, fmt.Errorf("%d fields, want %d", len(f), len(Fields))
	}

	var p Packet
	var err error

	p.Time, err = parseTime(f[fTime])
	if err != nil {
		return Packet{}, fmt.Errorf("time: %v", err)
	}

	// A packet is IPv4 or IPv6, so one of each pair is empty.
	p.SrcIP = source.NormIP(f[fSrc4] + f[fSrc6])
	p.DstIP = source.NormIP(f[fDst4] + f[fDst6])
	if p.SrcIP == "" || p.DstIP == "" {
		return Packet{}, fmt.Errorf("no address")
	}

	// Likewise it is TCP or UDP. The stream number tells us which.
	var srcPort, dstPort, stream string
	switch {
	case f[fTCPStream] != "":
		p.Proto = ProtoTCP
		srcPort, dstPort, stream = f[fTCPSrcPort], f[fTCPDstPort], f[fTCPStream]
	case f[fUDPStream] != "":
		p.Proto = ProtoUDP
		srcPort, dstPort, stream = f[fUDPSrcPort], f[fUDPDstPort], f[fUDPStream]
	default:
		return Packet{}, fmt.Errorf("neither TCP nor UDP")
	}

	p.Stream, err = strconv.Atoi(stream)
	if err != nil {
		return Packet{}, fmt.Errorf("stream: %v", err)
	}
	p.SrcPort, err = parsePort(srcPort)
	if err != nil {
		return Packet{}, fmt.Errorf("source port: %v", err)
	}
	p.DstPort, err = parsePort(dstPort)
	if err != nil {
		return Packet{}, fmt.Errorf("destination port: %v", err)
	}

	if p.Proto == ProtoTCP {
		// Printed as hex, for example 0x0012. Base 0 understands the 0x.
		flags, err := strconv.ParseUint(f[fFlags], 0, 16)
		if err != nil {
			return Packet{}, fmt.Errorf("flags: %v", err)
		}
		p.Flags = uint16(flags)
	}

	p.Len, err = strconv.Atoi(f[fLen])
	if err != nil {
		return Packet{}, fmt.Errorf("length: %v", err)
	}

	p.Protocol = f[fProtocol]
	p.Info = f[fInfo]
	p.ServerName = f[fServerName]
	p.Outbound = local.sentByUs(p)
	return p, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err
}

// parseTime reads seconds since 1970 with a fraction, "1760088879.123456",
// which is how tshark prints frame.time_epoch. Should a version print an
// RFC 3339 timestamp instead, that is accepted too.
func parseTime(s string) (time.Time, error) {
	seconds, fraction, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(seconds, 10, 64)
	if err != nil {
		return time.Parse(time.RFC3339Nano, s)
	}
	if fraction == "" {
		return time.Unix(sec, 0), nil
	}
	// Pad or cut the fraction to exactly nine digits: nanoseconds.
	fraction = (fraction + "000000000")[:9]
	nsec, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, nsec), nil
}

// Local is the set of this machine's own IP addresses. It tells us which
// direction a packet travels.
type Local map[string]bool

// LocalAddrs returns the addresses of all network interfaces.
func LocalAddrs() (Local, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := Local{}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			local[source.NormIP(ipnet.IP.String())] = true
		}
	}
	return local, nil
}

// sentByUs decides whether a packet was sent by this machine.
//
// Normally exactly one end is a local address and that settles it. When it
// does not (replaying a capture made on another network), we fall back on
// how ports work: clients use high, temporary ports and servers use low,
// well-known ones, so the end with the higher port is taken to be us.
func (l Local) sentByUs(p Packet) bool {
	srcIsLocal, dstIsLocal := l[p.SrcIP], l[p.DstIP]
	if srcIsLocal != dstIsLocal {
		return srcIsLocal
	}
	return p.SrcPort > p.DstPort
}

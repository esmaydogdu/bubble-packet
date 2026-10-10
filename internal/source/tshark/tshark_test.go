package tshark

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// line builds one tshark output line from the fields a test cares about.
func line(set map[int]string) string {
	f := make([]string, len(Fields))
	for i, v := range set {
		f[i] = v
	}
	return strings.Join(f, "\t")
}

var local = Local{"192.168.1.23": true, "2a02:a000::23": true}

func TestParseTCP(t *testing.T) {
	p, err := ParseLine(line(map[int]string{
		fTime: "1760088879.250000000", fSrc4: "192.168.1.23", fDst4: "140.82.121.4",
		fTCPSrcPort: "52311", fTCPDstPort: "443", fTCPStream: "7",
		fFlags: "0x0002", fLen: "78", fProtocol: "TCP",
		fInfo: "52311 → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460, WS=64",
	}), local)
	if err != nil {
		t.Fatal(err)
	}
	if p.Proto != ProtoTCP || p.Stream != 7 || p.SrcPort != 52311 || p.DstPort != 443 || p.Len != 78 {
		t.Errorf("parsed wrong: %+v", p)
	}
	if !p.Outbound {
		t.Errorf("packet from a local address should be outbound")
	}
	if !p.Has(FlagSYN) || p.Has(FlagACK) || p.FlagString() != "SYN" {
		t.Errorf("flags = %#x %q", p.Flags, p.FlagString())
	}
	if want := time.Unix(1760088879, 250000000); !p.Time.Equal(want) {
		t.Errorf("time = %v, want %v", p.Time, want)
	}
	if !strings.Contains(p.Info, ", WS=64") {
		t.Errorf("commas in Info must survive: %q", p.Info)
	}
}

func TestParseReplyAndFlags(t *testing.T) {
	p, err := ParseLine(line(map[int]string{
		fTime: "1760088879.27", fSrc4: "140.82.121.4", fDst4: "192.168.1.23",
		fTCPSrcPort: "443", fTCPDstPort: "52311", fTCPStream: "7",
		fFlags: "0x0012", fLen: "74", fProtocol: "TCP", fInfo: "443 → 52311 [SYN, ACK]",
	}), local)
	if err != nil {
		t.Fatal(err)
	}
	if p.Outbound {
		t.Errorf("packet to a local address should be inbound")
	}
	if p.FlagString() != "SYN, ACK" {
		t.Errorf("flags = %q", p.FlagString())
	}
	if p.Time.Nanosecond() != 270000000 {
		t.Errorf("short fraction parsed wrong: %v", p.Time.Nanosecond())
	}
}

func TestParseTLSClientHello(t *testing.T) {
	p, err := ParseLine(line(map[int]string{
		fTime: "1760088879.3", fSrc4: "192.168.1.23", fDst4: "140.82.121.4",
		fTCPSrcPort: "52311", fTCPDstPort: "443", fTCPStream: "7",
		fFlags: "0x0018", fLen: "583", fProtocol: "TLSv1.3", fInfo: "Client Hello (SNI=github.com)",
		fServerName: "github.com",
	}), local)
	if err != nil {
		t.Fatal(err)
	}
	if p.ServerName != "github.com" || p.Protocol != "TLSv1.3" || p.FlagString() != "PSH, ACK" {
		t.Errorf("parsed wrong: %+v", p)
	}
}

func TestParseUDPOverIPv6(t *testing.T) {
	p, err := ParseLine(line(map[int]string{
		fTime: "1760088880.0", fSrc6: "2A02:A000:0000:0000:0000:0000:0000:0023", fDst6: "2a00:1450:400e:811::200e",
		fUDPSrcPort: "61000", fUDPDstPort: "443", fUDPStream: "3",
		fLen: "1292", fProtocol: "QUIC", fInfo: "Initial, DCID=4f2a",
	}), local)
	if err != nil {
		t.Fatal(err)
	}
	if p.Proto != ProtoUDP || p.Stream != 3 || p.Flags != 0 || p.FlagString() != "" {
		t.Errorf("parsed wrong: %+v", p)
	}
	if p.SrcIP != "2a02:a000::23" || !p.Outbound {
		t.Errorf("IPv6 source not normalised or not seen as local: %q", p.SrcIP)
	}
}

func TestDirectionWithoutLocalAddresses(t *testing.T) {
	out, _ := ParseLine(line(map[int]string{
		fTime: "1", fSrc4: "10.0.0.5", fDst4: "1.1.1.1", fUDPSrcPort: "55555", fUDPDstPort: "53",
		fUDPStream: "0", fLen: "70",
	}), nil)
	in, _ := ParseLine(line(map[int]string{
		fTime: "2", fSrc4: "1.1.1.1", fDst4: "10.0.0.5", fUDPSrcPort: "53", fUDPDstPort: "55555",
		fUDPStream: "0", fLen: "90",
	}), nil)
	if !out.Outbound || in.Outbound {
		t.Errorf("port fallback wrong: out=%v in=%v", out.Outbound, in.Outbound)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"too few fields": "1760088879.0\t192.168.1.23",
		"no transport":   line(map[int]string{fTime: "1", fSrc4: "1.1.1.1", fDst4: "2.2.2.2", fLen: "60"}),
		"no address":     line(map[int]string{fTime: "1", fTCPSrcPort: "1", fTCPDstPort: "2", fTCPStream: "0", fFlags: "0x0002", fLen: "60"}),
		"bad time":       line(map[int]string{fTime: "yesterday", fSrc4: "1.1.1.1", fDst4: "2.2.2.2", fUDPSrcPort: "1", fUDPDstPort: "2", fUDPStream: "0", fLen: "60"}),
	}
	for name, in := range cases {
		if _, err := ParseLine(in, local); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestRFC3339Time(t *testing.T) {
	got, err := parseTime("2026-10-10T09:34:39.5Z")
	if err != nil || !got.Equal(time.Date(2026, 10, 10, 9, 34, 39, 500000000, time.UTC)) {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestArgs(t *testing.T) {
	got := strings.Join(Config{}.Args(), " ")
	if !strings.HasPrefix(got, "-l -n -i en0 -f tcp or udp -T fields -E occurrence=f -e frame.time_epoch") {
		t.Errorf("args = %q", got)
	}
	if n := strings.Count(got, " -e "); n != len(Fields) {
		t.Errorf("%d -e flags, want %d", n, len(Fields))
	}
}

// sampleCapture is what tshark would print: two good lines, an empty one and
// one that is not a packet.
var sampleCapture = strings.Join([]string{
	line(map[int]string{fTime: "1", fSrc4: "192.168.1.23", fDst4: "1.1.1.1", fTCPSrcPort: "50000", fTCPDstPort: "443", fTCPStream: "0", fFlags: "0x0002", fLen: "78"}),
	"",
	"garbage",
	line(map[int]string{fTime: "2", fSrc4: "1.1.1.1", fDst4: "192.168.1.23", fTCPSrcPort: "443", fTCPDstPort: "50000", fTCPStream: "0", fFlags: "0x0012", fLen: "74"}),
}, "\n")

func TestReadSkipsBadLines(t *testing.T) {
	out := make(chan Packet, 10)
	Read(strings.NewReader(sampleCapture), local, out)
	close(out)

	var got []Packet
	for p := range out {
		got = append(got, p)
	}
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	if !got[0].Outbound || got[1].Outbound {
		t.Errorf("directions wrong")
	}
}

func TestReplay(t *testing.T) {
	file := filepath.Join(t.TempDir(), "capture.tsv")
	if err := os.WriteFile(file, []byte(sampleCapture), 0o600); err != nil {
		t.Fatal(err)
	}
	feed, err := Replay(file, local)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range feed.Packets {
		n++
	}
	if n != 2 || feed.Err() != nil {
		t.Fatalf("packets=%d err=%v", n, feed.Err())
	}
	if _, err := Replay(filepath.Join(t.TempDir(), "missing"), local); err == nil {
		t.Errorf("want an error for a missing file")
	}
}

// fakeTshark writes a shell script that stands in for the tshark binary.
func fakeTshark(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tshark")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStartDeliversPacketsThenCloses(t *testing.T) {
	data := filepath.Join(t.TempDir(), "capture.tsv")
	if err := os.WriteFile(data, []byte(sampleCapture+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	feed, err := Start(context.Background(), Config{Path: fakeTshark(t, "cat "+data)})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range feed.Packets {
		n++
	}
	if n != 2 || feed.Err() != nil {
		t.Fatalf("packets=%d err=%v", n, feed.Err())
	}
}

func TestStartReportsWhyTsharkFailed(t *testing.T) {
	feed, err := Start(context.Background(), Config{Path: fakeTshark(t, "echo 'no such interface' >&2; exit 2")})
	if err != nil {
		t.Fatal(err)
	}
	for range feed.Packets {
	}
	if feed.Err() == nil || !strings.Contains(feed.Err().Error(), "no such interface") {
		t.Fatalf("err = %v, want tshark's message", feed.Err())
	}
}

func TestCancelStopsTshark(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	feed, err := Start(ctx, Config{Path: fakeTshark(t, "exec sleep 60")})
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	closed := make(chan struct{})
	go func() {
		for range feed.Packets {
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("feed did not close after cancel")
	}
	if feed.Err() != nil {
		t.Errorf("stopping on request is not a failure: %v", feed.Err())
	}
}

func TestStartMissingBinary(t *testing.T) {
	if _, err := Start(context.Background(), Config{Path: "no-such-tshark-binary"}); err == nil {
		t.Fatal("want an error for a missing binary")
	}
}

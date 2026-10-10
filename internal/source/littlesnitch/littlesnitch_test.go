package littlesnitch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Rows captured from a real machine, plus two broken ones.
const sample = `date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable
2026-10-10T09:34:39Z,out,65,192.168.1.1,,17,53,6,0,0,0,"/usr/sbin/mDNSResponder",
2026-10-10T09:34:39Z,out,0,17.188.185.137,43-courier.push.apple.com,6,5223,1,0,0,0,"/System/Library/PrivateFrameworks/ApplePushService.framework/apsd",
2026-10-10T09:34:39Z,out,0,13.107.5.93,,1,0,1,0,0,0,"path.opt/homebrew/Cellar/mtr/*/sbin/mtr-packet",
not,a,row
2026-10-10T09:34:40Z,sideways,0,1.2.3.4,,6,443,0,0,0,0,"/bin/x",
2026-10-10T09:34:40Z,out,0,17.188.185.137,43-courier.push.apple.com,6,5223,0,0,4806,9190,"/System/Library/PrivateFrameworks/ApplePushService.framework/apsd",
2026-10-10T09:34:41Z,in,501,2A00:1450:400E:0811:0000:0000:0000:200E,,6,49152,1,0,10,20,"/usr/libexec/helper","/Applications/Safari.app"
`

// readAll runs Read over a string and collects what it sends.
func readAll(in string) []Stat {
	out := make(chan Stat, 100)
	Read(strings.NewReader(in), out)
	close(out)

	var stats []Stat
	for s := range out {
		stats = append(stats, s)
	}
	return stats
}

func TestRead(t *testing.T) {
	stats := readAll(sample)
	if len(stats) != 5 {
		t.Fatalf("got %d rows, want 5 (the two broken ones skipped)", len(stats))
	}

	dns := stats[0]
	if !dns.Outbound || dns.UID != 65 || dns.IP != "192.168.1.1" || dns.Hostname != "" ||
		dns.Proto != 17 || dns.Port != 53 || dns.Connects != 6 {
		t.Errorf("dns row parsed wrong: %+v", dns)
	}
	if want := time.Date(2026, 10, 10, 9, 34, 39, 0, time.UTC); !dns.Time.Equal(want) {
		t.Errorf("time = %v, want %v", dns.Time, want)
	}
	if got := AppName(dns.AppID()); got != "mDNSResponder" {
		t.Errorf("app name = %q", got)
	}

	if icmp := stats[2]; icmp.Proto != 1 || icmp.Port != 0 || AppName(icmp.AppID()) != "mtr-packet" {
		t.Errorf("icmp row parsed wrong: %+v", icmp)
	}

	if push := stats[3]; push.BytesIn != 4806 || push.BytesOut != 9190 || push.Hostname != "43-courier.push.apple.com" {
		t.Errorf("push row parsed wrong: %+v", push)
	}

	in := stats[4]
	if in.Outbound || in.Port != 49152 {
		t.Errorf("inbound row parsed wrong: %+v", in)
	}
	if in.IP != "2a00:1450:400e:811::200e" {
		t.Errorf("IPv6 not normalised: %q", in.IP)
	}
	if in.AppID() != "/Applications/Safari.app" || AppName(in.AppID()) != "Safari" {
		t.Errorf("parent app not preferred: %q", in.AppID())
	}
}

func TestHeaderOnly(t *testing.T) {
	header := strings.SplitAfter(sample, "\n")[0]
	if stats := readAll(header); len(stats) != 0 {
		t.Fatalf("got %d rows from a header-only log", len(stats))
	}
}

func TestArgs(t *testing.T) {
	if got := strings.Join(Config{}.Args(), " "); got != "log-traffic --stream" {
		t.Errorf("args = %q", got)
	}
	since := time.Date(2026, 10, 10, 11, 0, 0, 0, time.Local)
	got := Config{Since: since}.Args()
	if len(got) != 4 || got[2] != "--begin-date" || got[3] != "2026-10-10 11:00:00" {
		t.Errorf("args = %q", got)
	}
}

func TestReplay(t *testing.T) {
	file := filepath.Join(t.TempDir(), "traffic.csv")
	if err := os.WriteFile(file, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	feed, err := Replay(file)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range feed.Stats {
		n++
	}
	if n != 5 || feed.Err() != nil {
		t.Fatalf("rows=%d err=%v", n, feed.Err())
	}
}

// fakeLittleSnitch writes a shell script that stands in for the real binary.
func fakeLittleSnitch(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "littlesnitch")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStartDeliversRowsThenCloses(t *testing.T) {
	data := filepath.Join(t.TempDir(), "traffic.csv")
	if err := os.WriteFile(data, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	feed, err := Start(context.Background(), Config{Path: fakeLittleSnitch(t, "cat "+data)})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range feed.Stats {
		n++
	}
	if n != 5 || feed.Err() != nil {
		t.Fatalf("rows=%d err=%v", n, feed.Err())
	}
}

func TestStartReportsWhyItFailed(t *testing.T) {
	feed, err := Start(context.Background(), Config{Path: fakeLittleSnitch(t, "echo 'must be run as root' >&2; exit 1")})
	if err != nil {
		t.Fatal(err)
	}
	for range feed.Stats {
	}
	if feed.Err() == nil || !strings.Contains(feed.Err().Error(), "must be run as root") {
		t.Fatalf("err = %v, want littlesnitch's message", feed.Err())
	}
}

func TestCancelStopsLittleSnitch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	feed, err := Start(ctx, Config{Path: fakeLittleSnitch(t, "exec sleep 60")})
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	closed := make(chan struct{})
	go func() {
		for range feed.Stats {
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

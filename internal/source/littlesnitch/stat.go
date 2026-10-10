// Package littlesnitch reads the traffic log of the Little Snitch firewall:
// which app talked to which host, and how much.
//
// The data comes from `littlesnitch log-traffic --stream`, which needs root
// and the Little Snitch setting "Allow access via Terminal".
//
// The package has two files:
//
//	stat.go  what a Stat is, and turning one CSV row into one
//	feed.go  running littlesnitch and delivering Stats on a channel
package littlesnitch

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"bubble-packet/internal/source"
)

// Stat is one row of the traffic log.
//
// A row is not a single event. It holds the totals for one app and one remote
// address over the interval since the previous row, so counts must be added up.
type Stat struct {
	Time       time.Time // start of the interval, UTC
	Outbound   bool      // false for connections coming in to this Mac
	UID        int       // user the process runs as; 0 is root
	IP         string    // remote address
	Hostname   string    // name the app looked up to get IP; may be empty
	Proto      uint8     // IP protocol number: 6 TCP, 17 UDP, 1 ICMP
	Port       uint16    // remote port when Outbound, local port otherwise
	Connects   int       // new connections in the interval
	Denies     int       // connection attempts Little Snitch blocked
	BytesIn    uint64
	BytesOut   uint64
	Executable string // the process that made the connection
	ParentApp  string // the app responsible for it; may be empty
}

// AppID identifies the app a row belongs to: the responsible app when Little
// Snitch found one, otherwise the connecting process itself.
func (s Stat) AppID() string {
	if s.ParentApp != "" {
		return s.ParentApp
	}
	return s.Executable
}

// AppName turns an AppID into a short display name:
// "/Applications/Safari.app" and "/usr/sbin/mDNSResponder" become "Safari"
// and "mDNSResponder".
func AppName(id string) string {
	name := path.Base(strings.TrimRight(id, "/"))
	name = strings.TrimSuffix(name, ".app")
	if name == "" || name == "." {
		return "unknown"
	}
	return name
}

// The position of each column in a row, in the order Little Snitch prints
// them:
//
//	date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,
//	denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable
const (
	colDate = iota
	colDirection
	colUID
	colIP
	colHostname
	colProtocol
	colPort
	colConnects
	colDenies
	colBytesIn
	colBytesOut
	colExecutable
	colParentApp
)

// ParseRecord converts one CSV row, already split into fields, into a Stat.
func ParseRecord(rec []string) (Stat, error) {
	// The last column, the parent app, is empty on most rows and may be
	// missing altogether.
	if len(rec) < colParentApp {
		return Stat{}, fmt.Errorf("%d fields, want at least %d", len(rec), colParentApp)
	}

	var s Stat
	var err error

	s.Time, err = time.Parse(time.RFC3339, rec[colDate])
	if err != nil {
		return Stat{}, fmt.Errorf("date: %v", err)
	}

	switch rec[colDirection] {
	case "out":
		s.Outbound = true
	case "in":
		s.Outbound = false
	default:
		return Stat{}, fmt.Errorf("direction: %q", rec[colDirection])
	}

	s.UID, err = strconv.Atoi(rec[colUID])
	if err != nil {
		return Stat{}, fmt.Errorf("uid: %v", err)
	}

	s.IP = source.NormIP(rec[colIP])
	s.Hostname = rec[colHostname]

	proto, err := strconv.ParseUint(rec[colProtocol], 10, 8)
	if err != nil {
		return Stat{}, fmt.Errorf("protocol: %v", err)
	}
	s.Proto = uint8(proto)

	port, err := strconv.ParseUint(rec[colPort], 10, 16)
	if err != nil {
		return Stat{}, fmt.Errorf("port: %v", err)
	}
	s.Port = uint16(port)

	s.Connects, err = strconv.Atoi(rec[colConnects])
	if err != nil {
		return Stat{}, fmt.Errorf("connectCount: %v", err)
	}
	s.Denies, err = strconv.Atoi(rec[colDenies])
	if err != nil {
		return Stat{}, fmt.Errorf("denyCount: %v", err)
	}
	s.BytesIn, err = strconv.ParseUint(rec[colBytesIn], 10, 64)
	if err != nil {
		return Stat{}, fmt.Errorf("byteCountIn: %v", err)
	}
	s.BytesOut, err = strconv.ParseUint(rec[colBytesOut], 10, 64)
	if err != nil {
		return Stat{}, fmt.Errorf("byteCountOut: %v", err)
	}

	s.Executable = rec[colExecutable]
	if len(rec) > colParentApp {
		s.ParentApp = rec[colParentApp]
	}
	return s, nil
}

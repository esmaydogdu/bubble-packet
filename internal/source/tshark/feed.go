package tshark

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Feed delivers packets as tshark captures them.
//
// Receive from Packets until it is closed. Closed means tshark has stopped;
// Err then says why.
type Feed struct {
	Packets <-chan Packet
	err     error
}

// Err reports why the feed ended: nil if we stopped it ourselves, otherwise
// tshark's own error message. Call it only after Packets has been closed.
func (f *Feed) Err() error { return f.err }

// Config says how to run tshark.
type Config struct {
	Path  string // the tshark binary; "tshark" if empty
	Iface string // capture interface; "en0" if empty
}

// Args returns the command-line arguments Start passes to tshark.
//
//	-l              flush after every packet, so lines arrive immediately
//	-n              no name lookups, so the capture causes no DNS traffic
//	-i en0          the interface to capture on
//	-f "tcp or udp" capture filter, in Berkeley Packet Filter syntax
//	-T fields       print only the fields named with -e, tab separated
//	-E occurrence=f when a field occurs twice in a packet, print the first
func (c Config) Args() []string {
	iface := c.Iface
	if iface == "" {
		iface = "en0"
	}
	args := []string{"-l", "-n", "-i", iface, "-f", "tcp or udp", "-T", "fields", "-E", "occurrence=f"}
	for _, field := range Fields {
		args = append(args, "-e", field)
	}
	return args
}

// Start runs tshark and returns a feed of the packets it captures.
// Cancelling ctx stops tshark, which closes the feed.
func Start(ctx context.Context, cfg Config) (*Feed, error) {
	local, err := LocalAddrs()
	if err != nil {
		return nil, fmt.Errorf("local addresses: %v", err)
	}

	path := cfg.Path
	if path == "" {
		path = "tshark"
	}

	// Set up the process. Its standard output (the packet lines) comes to
	// us through a pipe; its standard error (messages for humans) is kept
	// in a buffer so we can report it if tshark fails.
	cmd := exec.CommandContext(ctx, path, cfg.Args()...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tshark: %v", err)
	}

	// The channel holds up to 1000 packets, so a short burst does not make
	// tshark wait for the UI.
	packets := make(chan Packet, 1000)
	feed := &Feed{Packets: packets}

	// "go" starts this function in the background and Start returns
	// straight away. The function runs until tshark's output ends.
	go func() {
		Read(stdout, local, packets)

		// The output ended, so tshark has exited or is about to.
		// Wait collects its exit status. If we did not ask it to stop,
		// that is a failure worth reporting.
		err := cmd.Wait()
		if err != nil && ctx.Err() == nil {
			feed.err = fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}

		// Closing tells the receiver that no more packets will come.
		close(packets)
	}()

	return feed, nil
}

// Read parses tshark output from r line by line and sends each packet to
// out. It returns when r has no more lines. Lines that cannot be parsed are
// skipped.
func Read(r io.Reader, local Local, out chan<- Packet) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 1024*1024) // allow long lines
	for scanner.Scan() {
		packet, err := ParseLine(scanner.Text(), local)
		if err != nil {
			continue
		}
		out <- packet // waits here while the channel is full
	}
}

// Replay returns a feed of the packets in a saved capture: the output of
// the tshark command above, redirected to a file. It needs neither tshark
// nor root. local may be nil.
func Replay(file string, local Local) (*Feed, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	packets := make(chan Packet, 1000)
	go func() {
		Read(f, local, packets)
		f.Close()
		close(packets)
	}()

	return &Feed{Packets: packets}, nil
}

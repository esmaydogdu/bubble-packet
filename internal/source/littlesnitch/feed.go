package littlesnitch

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Feed delivers traffic log rows as Little Snitch writes them.
//
// Receive from Stats until it is closed. Closed means littlesnitch has
// stopped; Err then says why.
type Feed struct {
	Stats <-chan Stat
	err   error
}

// Err reports why the feed ended: nil if we stopped it ourselves, otherwise
// littlesnitch's own error message (this is where "needs root" shows up).
// Call it only after Stats has been closed.
func (f *Feed) Err() error { return f.err }

// Config says how to run the Little Snitch command.
type Config struct {
	Path  string    // the littlesnitch binary; "littlesnitch" if empty
	Since time.Time // also load history from this moment; zero for live only
}

// Args returns the command-line arguments Start passes to littlesnitch.
func (c Config) Args() []string {
	args := []string{"log-traffic", "--stream"}
	if !c.Since.IsZero() {
		args = append(args, "--begin-date", c.Since.Local().Format("2006-01-02 15:04:05"))
	}
	return args
}

// Start runs littlesnitch and returns a feed of the rows it prints.
// Cancelling ctx stops littlesnitch, which closes the feed.
func Start(ctx context.Context, cfg Config) (*Feed, error) {
	path := cfg.Path
	if path == "" {
		path = "littlesnitch"
	}

	// Set up the process. Its standard output (the CSV rows) comes to us
	// through a pipe; its standard error (messages for humans) is kept in
	// a buffer so we can report it if littlesnitch fails.
	cmd := exec.CommandContext(ctx, path, cfg.Args()...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start littlesnitch: %v", err)
	}

	stats := make(chan Stat, 1000)
	feed := &Feed{Stats: stats}

	// "go" starts this function in the background and Start returns
	// straight away. The function runs until littlesnitch's output ends.
	go func() {
		Read(stdout, stats)

		// The output ended, so littlesnitch has exited or is about to.
		// Wait collects its exit status. If we did not ask it to stop,
		// that is a failure worth reporting.
		err := cmd.Wait()
		if err != nil && ctx.Err() == nil {
			feed.err = fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}

		// Closing tells the receiver that no more rows will come.
		close(stats)
	}()

	return feed, nil
}

// Read parses Little Snitch's CSV from r and sends each row to out. It
// returns when r has no more rows. The header and any row that cannot be
// parsed are skipped.
func Read(r io.Reader, out chan<- Stat) {
	rows := csv.NewReader(r)
	rows.FieldsPerRecord = -1 // rows may differ in length; ParseRecord checks
	rows.LazyQuotes = true    // executable paths are not always cleanly quoted

	for {
		rec, err := rows.Read()
		if err != nil {
			// A malformed row: skip it and carry on with the next.
			var bad *csv.ParseError
			if errors.As(err, &bad) {
				continue
			}
			// Anything else, including the normal end of input: stop.
			return
		}
		if rec[colDate] == "date" {
			continue // the header row
		}
		stat, err := ParseRecord(rec)
		if err != nil {
			continue
		}
		out <- stat // waits here while the channel is full
	}
}

// Replay returns a feed of the rows in a saved log, for working without
// root.
func Replay(file string) (*Feed, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	stats := make(chan Stat, 1000)
	go func() {
		Read(f, stats)
		f.Close()
		close(stats)
	}()

	return &Feed{Stats: stats}, nil
}

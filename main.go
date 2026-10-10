package main

import (
	"bubble-packet/internal/source/littlesnitch"
	"bubble-packet/internal/source/tshark"
	"bubble-packet/internal/store"
	"bubble-packet/internal/ui"
	"context"
	"fmt"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	packetFeed, err := tshark.Start(ctx, tshark.Config{})

	if err != nil {
		fmt.Println("error tshark:", err)
		os.Exit(1)
	}

	// Little Snitch tells us which app owns each connection. It is optional:
	// if it cannot be started, the app runs without app names. The last ten
	// minutes of its log are loaded too, so connections that are already
	// running get a name.
	statFeed, err := littlesnitch.Start(ctx, littlesnitch.Config{
		Since: time.Now().Add(-10 * time.Minute),
	})
	if err != nil {
		statFeed = nil
	}

	p := tea.NewProgram(ui.New(store.New(), packetFeed, statFeed))
	_, err = p.Run()

	cancel()
	// Wait until both tools have really stopped: each channel closes when
	// its tool has.
	for range packetFeed.Packets {
	}
	if statFeed != nil {
		for range statFeed.Stats {
		}
	}

	if err != nil {
		fmt.Printf("An error: %v", err)
		os.Exit(1)
	}

}

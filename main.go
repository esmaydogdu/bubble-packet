package main

import (
	"bubble-packet/internal/source/tshark"
	"bubble-packet/internal/store"
	"bubble-packet/internal/ui"
	"context"
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	packetFeed, err := tshark.Start(ctx, tshark.Config{})

	if err != nil {
		fmt.Println("error tshark:", err)
		os.Exit(1)
	}

	p := tea.NewProgram(ui.New(store.New(), packetFeed))
	_, err = p.Run()

	cancel()
	// Wait until tshark has really stopped: the channel closes when it has.
	for range packetFeed.Packets {
	}

	if err != nil {
		fmt.Printf("An error: %v", err)
		os.Exit(1)
	}

}

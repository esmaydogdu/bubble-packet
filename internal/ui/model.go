package ui

import (
	"bubble-packet/internal/source/tshark"
	"bubble-packet/internal/store"
	"fmt"

	tea "charm.land/bubbletea/v2"
)

type Model struct {
	choices    []store.Connection
	cursor     int
	store      *store.Store
	packetFeed *tshark.Feed
	err        error
	paused     bool
}

// packetMsg is one captured packet, delivered to Update.
type packetMsg tshark.Packet

type feedEndedMsg struct {
	name string
	err  error
}

// waitForPacket returns a command that waits for the next packet.
func waitForPacket(f *tshark.Feed) tea.Cmd {
	return func() tea.Msg {
		packet, ok := <-f.Packets

		if !ok {
			return feedEndedMsg{name: "tshark", err: f.Err()}
		}
		return packetMsg(packet)
	}
}

func New(s *store.Store, packetFeed *tshark.Feed) Model {
	return Model{
		store:      s,
		choices:    s.Connections(),
		packetFeed: packetFeed,
	}
}

func (m Model) Init() tea.Cmd {
	return waitForPacket(m.packetFeed)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {

		case "ctrl+c", "q":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}

		case "space":
			m.paused = !m.paused
		}
	case packetMsg:
		m.store.AddPacket(tshark.Packet(msg))

		if m.paused {
			return m, waitForPacket(m.packetFeed)
		}

		var selected store.ConnKey
		hadSelection := m.cursor < len(m.choices)
		if hadSelection {
			selected = m.choices[m.cursor].Key
		}

		m.choices = m.store.Connections()

		if hadSelection {
			for i, c := range m.choices {
				if c.Key == selected {
					m.cursor = i
					break
				}
			}
		}

		return m, waitForPacket(m.packetFeed)

	case feedEndedMsg:
		m.err = msg.err
	}

	return m, nil
}

func (m Model) View() tea.View {
	t := m.store.Totals()
	s := fmt.Sprintf("Connections: %d   Packets: %d", t.Connections, t.Packets)
	if m.paused {
		s += "   (paused, space to resume)"
	}
	s += "\n\n"

	if m.err != nil {
		s += fmt.Sprintf("tshark stopped: %v\n\n", m.err)
	}

	for i, c := range m.choices {
		if i >= 30 {
			break
		}
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}
		s += fmt.Sprintf("%s %-32s %-8s %s\n", cursor, c.Label(), c.Protocol, c.State)
	}

	s += "\nPress q to quit.\n"
	return tea.NewView(s)
}

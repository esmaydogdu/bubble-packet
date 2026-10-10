package ui

import (
	"bubble-packet/internal/source/littlesnitch"
	"bubble-packet/internal/source/tshark"
	"bubble-packet/internal/store"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true)
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244")) // grey
	outStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))  // blue: sent by you
	inStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214")) // orange: received
	openStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))  // green: SYN
	closeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("220")) // yellow: FIN
	resetStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // red: RST
)

type screen int

const (
	screenList screen = iota
	screenPackets
	screenPacket
)

type Model struct {
	choices      []store.Connection
	cursor       int
	store        *store.Store
	packetFeed   *tshark.Feed
	statFeed     *littlesnitch.Feed // nil when Little Snitch is not available
	err          error
	paused       bool
	screen       screen
	packetCursor int
	openKey      store.ConnKey
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

// statMsg is one Little Snitch row, delivered to Update.
type statMsg littlesnitch.Stat

// waitForStat returns a command that waits for the next Little Snitch row.
func waitForStat(f *littlesnitch.Feed) tea.Cmd {
	return func() tea.Msg {
		stat, ok := <-f.Stats

		if !ok {
			return feedEndedMsg{name: "littlesnitch", err: f.Err()}
		}
		return statMsg(stat)
	}
}

// New builds the first model. statFeed may be nil: the app then runs without
// app names.
func New(s *store.Store, packetFeed *tshark.Feed, statFeed *littlesnitch.Feed) Model {
	return Model{
		store:      s,
		choices:    s.Connections(),
		packetFeed: packetFeed,
		statFeed:   statFeed,
	}
}

// Init starts one waiting loop per feed.
func (m Model) Init() tea.Cmd {
	if m.statFeed == nil {
		return waitForPacket(m.packetFeed)
	}
	return tea.Batch(waitForPacket(m.packetFeed), waitForStat(m.statFeed))
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {

		case "ctrl+c", "q":
			return m, tea.Quit

		case "up", "k":
			switch m.screen {
			case screenList:
				if m.cursor > 0 {
					m.cursor--
				}
			case screenPackets:
				if m.packetCursor > 0 {
					m.packetCursor--
				}
			}

		case "down", "j":
			switch m.screen {
			case screenList:
				if m.cursor < len(m.choices)-1 {
					m.cursor++
				}
			case screenPackets:
				last := min(len(m.store.Packets(m.openKey)), 40) - 1
				if m.packetCursor < last {
					m.packetCursor++
				}
			}

		case "space":
			m.paused = !m.paused

		case "enter":
			switch m.screen {
			case screenList:
				if len(m.choices) > 0 {
					m.openKey = m.choices[m.cursor].Key
					m.packetCursor = 0
					m.screen = screenPackets
				}
			case screenPackets:
				if len(m.store.Packets(m.openKey)) > 0 {
					m.screen = screenPacket
				}
			}

		case "esc":
			switch m.screen {
			case screenPacket:
				m.screen = screenPackets
				m.packetCursor = 0

			case screenPackets:
				m.screen = screenList
				m.cursor = 0
			}

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

	case statMsg:
		// Little Snitch says which app talks to which address. The store
		// uses that to fill in the Apps of matching connections.
		m.store.AddTraffic(littlesnitch.Stat(msg))
		return m, waitForStat(m.statFeed)

	case feedEndedMsg:
		if msg.err != nil {
			m.err = fmt.Errorf("%s stopped: %v", msg.name, msg.err)
			if msg.name == "littlesnitch" {
				m.err = fmt.Errorf("no app names (run with sudo): %v", msg.err)
			}
		}
	}

	return m, nil
}

// packetsView draws the packets of the connection that was opened with enter.
func (m Model) packetsView() string {
	c, ok := m.store.Connection(m.openKey)
	if !ok {
		return "This connection is gone. Press esc to go back.\n"
	}

	s := titleStyle.Render(c.Label()) + fmt.Sprintf("   %s   %s   %s   %d packets\n\n", appNames(c), c.Protocol, c.State, c.Packets)
	s += dimStyle.Render(fmt.Sprintf("  %8s  %2s  %-8s  %-13s  %5s  %s",
		"SECONDS", "", "PROTO", "FLAGS", "BYTES", "INFO")) + "\n"

	for i, p := range m.store.Packets(m.openKey) {
		if i >= 40 {
			break
		}

		cursor := " "
		if i == m.packetCursor {
			cursor = ">"
		}

		arrow := outStyle.Render("->")
		if !p.Outbound {
			arrow = inStyle.Render("<-")
		}

		// Pick a colour for the flags by what they mean.
		flagStyle := dimStyle
		switch {
		case p.Has(tshark.FlagRST):
			flagStyle = resetStyle
		case p.Has(tshark.FlagFIN):
			flagStyle = closeStyle
		case p.Has(tshark.FlagSYN):
			flagStyle = openStyle
		}
		// Pad first, then colour. See the note below.
		flags := flagStyle.Render(fmt.Sprintf("%-13s", p.FlagString()))

		seconds := p.Time.Sub(c.First).Seconds()

		s += fmt.Sprintf("%s %8.3f  %s  %-8s  %s  %5d  %s\n",
			cursor, seconds, arrow, p.Protocol, flags, p.Len, dimStyle.Render(shorten(p.Info, 70)))
	}

	s += "\nEnter opens a packet. Press esc to go back.\n"
	return s
}

// packetView shows everything we know about the packet that was opened with
// enter on the packets screen.
func (m Model) packetView() string {
	packets := m.store.Packets(m.openKey)
	if m.packetCursor >= len(packets) {
		return "This packet is gone. Press esc to go back.\n"
	}
	p := packets[m.packetCursor]

	direction := outStyle.Render("-> sent by this Mac")
	if !p.Outbound {
		direction = inStyle.Render("<- received")
	}

	s := titleStyle.Render(fmt.Sprintf("Packet %d of %d", m.packetCursor+1, len(packets))) + "\n\n"
	s += fmt.Sprintf("%-10s %s\n", "Time", p.Time.Format("15:04:05.000"))
	s += fmt.Sprintf("%-10s %s\n", "Direction", direction)
	s += fmt.Sprintf("%-10s %s port %d\n", "From", p.SrcIP, p.SrcPort)
	s += fmt.Sprintf("%-10s %s port %d\n", "To", p.DstIP, p.DstPort)
	s += fmt.Sprintf("%-10s %s\n", "Protocol", p.Protocol)
	if p.Proto == tshark.ProtoTCP {
		s += fmt.Sprintf("%-10s %s\n", "Flags", p.FlagString())
	}
	s += fmt.Sprintf("%-10s %d bytes\n", "Size", p.Len)
	if p.ServerName != "" {
		s += fmt.Sprintf("%-10s %s\n", "Server", p.ServerName)
	}
	s += "\n" + p.Info + "\n"

	s += "\nPress esc to go back.\n"
	return s
}

func (m Model) View() tea.View {
	switch m.screen {
	case screenPackets:
		return tea.NewView(m.packetsView())

	case screenPacket:
		return tea.NewView(m.packetView())
	}

	t := m.store.Totals()
	s := fmt.Sprintf("Connections: %d   Packets: %d", t.Connections, t.Packets)

	if m.paused {
		s += "   (paused, space to resume)"
	}
	s += "\n\n"

	if m.err != nil {
		s += resetStyle.Render(shorten(m.err.Error(), 100)) + "\n\n"
	}

	s += dimStyle.Render(fmt.Sprintf("  %-16s %-32s %-8s %-10s %6s %8s", "APP", "REMOTE", "PROTO", "STATE", "PKTS", "BYTES")) + "\n"

	for i, c := range m.choices {
		if i >= 30 {
			break
		}
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}
		s += fmt.Sprintf("%s %-16s %-32s %-8s %-10s %6d %8d\n",
			cursor, shorten(appNames(c), 16), shorten(c.Label(), 32), c.Protocol, c.State, c.Packets, c.Bytes())
	}

	s += "\nPress q to quit.\n"
	return tea.NewView(s)
}

// appNames is the text for the APP column: the app that owns a connection,
// "Safari+Slack" when two apps use the same server, or "-" when Little Snitch
// has not told us yet.
func appNames(c store.Connection) string {
	if len(c.Apps) == 0 {
		return "-"
	}
	return strings.Join(c.Apps, "+")
}

// shorten cuts s to at most max characters, ending with "…" if it was cut.
func shorten(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

# bubble-packet: spec

An interactive terminal app, written in Go with Bubble Tea, for examining your
own Mac's network traffic live at three levels: apps, connections and packets.

## 1. Goals

- Learn networking by seeing real traffic: ports, protocols, DNS, TCP and TLS
  handshakes.
- Refresh Go and learn Bubble Tea.

## 2. Out of scope

- Decrypting request or response bodies.
- Traffic from other devices on the network.
- The ML classifier. The connection grouping built here becomes its input later.
- Changing Little Snitch rules or settings. The app only reads.

## 3. Environment

- macOS, run with `sudo` (both data sources need root).
- Bubble Tea v2: `charm.land/bubbletea/v2` (v2.1.0 is already in go.mod).
  v2 API in use: `tea.KeyPressMsg`, `View() tea.View`, `tea.NewView(s)`.
  Do not use v1 examples (`github.com/charmbracelet/bubbletea`).
- Bubbles v2 for the table and text input: module `charm.land/bubbles/v2`.
- Lip Gloss v2 for layout and borders.
- Little Snitch with Settings > Security > "Allow access via Terminal" enabled.
- Wireshark installed, for its CLI `tshark`.

## 4. Data sources

### 4.1 Little Snitch

Command:

    littlesnitch log-traffic --stream

Output is CSV. The first line is the header:

    date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable

Sample rows from this machine:

    2026-10-10T09:34:39Z,out,65,192.168.1.1,,17,53,6,0,0,0,"/usr/sbin/mDNSResponder",
    2026-10-10T09:34:39Z,out,0,17.188.185.137,43-courier.push.apple.com,6,5223,1,0,0,0,"/System/Library/PrivateFrameworks/ApplePushService.framework/apsd",
    2026-10-10T09:34:39Z,out,0,13.107.5.93,,1,0,1,0,0,0,"path.opt/homebrew/Cellar/mtr/*/sbin/mtr-packet",
    2026-10-10T09:34:40Z,out,0,17.188.185.137,43-courier.push.apple.com,6,5223,0,0,4806,9190,"/System/Library/PrivateFrameworks/ApplePushService.framework/apsd",

Rules:

- Each row is statistics for the interval since the previous row, not a single
  event. Byte and connect counts are deltas: add them up.
- `date` is RFC 3339 in UTC. Display in local time.
- `protocol` is the IP protocol number: 6 TCP, 17 UDP, 1 ICMP (port is 0).
- `port` is the remote port for `out` rows and the local port for `in` rows.
- `remoteHostname` and `parentAppExecutable` may be empty.
- Executable fields are quoted and are not always clean paths (see the `mtr`
  row). Parse with `encoding/csv`, never by splitting on commas.
- App identity: `parentAppExecutable` if set, else `connectingExecutable`.
  Display name is the last path element.
- Without `--stream` or `--begin-date` the command prints only the header.
  `--begin-date "YYYY-MM-DD HH:MM:SS"` can be combined with `--stream` to
  preload history.

### 4.2 tshark

One capture runs for the whole lifetime of the app (always on).

Command:

    tshark -l -n -i en0 -f "tcp or udp" -T fields -E occurrence=f \
      -e frame.time_epoch \
      -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst \
      -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport \
      -e tcp.stream -e udp.stream \
      -e tcp.flags -e frame.len \
      -e _ws.col.protocol -e _ws.col.info \
      -e tls.handshake.extensions_server_name

Rules:

- One line per packet, 16 tab-separated fields in the order above. Tab is the
  default separator and is required, because the Info column contains commas.
- A field that does not apply is an empty string. Exactly one of each
  v4/v6 and tcp/udp pair is filled.
- `-l` flushes after every packet. `-n` turns off name lookups, so the capture
  itself creates no DNS traffic.
- `tcp.flags` is hex, for example `0x0012`. Bits: FIN 0x001, SYN 0x002,
  RST 0x004, PSH 0x008, ACK 0x010.
- TCP and UDP stream numbers are separate counters. A connection key is
  (protocol, stream number).
- The server name is present only on the TLS Client Hello packet.
- Direction: a packet is outbound when its source address is one of this
  machine's addresses (`net.InterfaceAddrs()`).

## 5. Architecture

Three layers. Each knows only the layer below it.

    bubble-packet/
      main.go                  flags, wiring, starts the program
      internal/
        source/
          littlesnitch/        runs the command, parses CSV into Stat
          tshark/              runs the command, parses lines into Packet
        store/                 in-memory state and all grouping logic
        ui/                    Bubble Tea model, Update, View
      testdata/                recorded samples of both outputs

### 5.1 Sources (implemented)

Each source is a small package with no generics and one background goroutine.

- `tshark`: `packet.go` (the `Packet` type), `parse.go` (one line to one
  `Packet`), `feed.go` (run tshark, deliver packets).
- `littlesnitch`: `stat.go` (the `Stat` type and row parsing), `feed.go` (run
  littlesnitch, deliver rows).
- `source/ip.go`: `NormIP`, the one helper they share.

Starting a source returns a feed holding a receive-only channel:

    feed, err := tshark.Start(ctx, tshark.Config{})         // feed.Packets <-chan tshark.Packet
    feed, err := littlesnitch.Start(ctx, littlesnitch.Config{}) // feed.Stats <-chan littlesnitch.Stat

- One value is sent per packet or row. Receive until the channel is closed,
  then read `feed.Err()`: nil if we stopped it, otherwise the tool's own error
  message (this is how a missing `sudo` or a wrong interface shows up).
- Lines that cannot be parsed are skipped.
- Cancelling the context stops the child process, which closes the channel.
- `tshark.Replay(file, local)` and `littlesnitch.Replay(file)` give the same
  feed from a saved file.
- Sources import neither Bubble Tea nor the store.

### 5.2 Store (implemented)

Plain Go, no UI imports, unit tested. The row types and their doc comments
are in `internal/store/rows.go`; that file is the contract the UI builds on.

Writes:

    s.AddTraffic(littlesnitch.Stat)
    s.AddPacket(tshark.Packet)

Reads (all return copies, safe to keep, sort and filter):

    s.Connections() []Connection          // all, newest first
    s.Connection(key) (Connection, bool)  // one, false if evicted
    s.Packets(key) []tshark.Packet        // oldest first
    s.Apps() []AppRow                     // busiest first
    s.Hosts(appID) []HostRow
    s.ConnectionsFor(host) []Connection
    s.Totals() Totals                     // for a status bar

A `Connection` carries: `Key`, `Protocol` ("TLSv1.3", "QUIC", "DNS", or
"TCP"/"UDP" until known), local and remote address and port, `ServerName`,
`Hostname`, `Apps`, `First`, `Last`, `Packets`, `Kept`, `BytesIn`, `BytesOut`,
`State`, and the helpers `Label()`, `Bytes()`, `Duration()`.

Demo data, for building the UI without root or live sources:

    s := store.Demo()        // one example of every case the UI must draw
    store.DemoTick(s, n)     // call on a timer, n = 1, 2, 3, ... to simulate live traffic

Connection state, derived from flags:

| State | Rule |
|---|---|
| opening | SYN seen, handshake not complete |
| open | SYN-ACK seen, then an ACK |
| midstream | first packet seen had no SYN (capture started late) |
| closing | one FIN seen |
| closed | FIN seen in both directions |
| reset | RST seen |
| active / idle | UDP: packet within the last 30 s, or not |

### 5.3 Joining the two sources

The sources do not match row for row. The join is a lookup:

- `AddTraffic` maintains an index from (remote IP, remote port, protocol) to
  the set of apps seen using it. Only `out` rows are indexed.
- A connection's `Apps` is that lookup for its remote address.
- If two apps use the same address (shared CDNs), the connection lists both.
- tshark cannot tell which app owns a packet. With two apps on one server,
  each connection lists both apps, and a filter on either app shows it.
- If Little Snitch has not reported the address yet, `Apps` is empty and is
  filled in when the row arrives.
- Matching is by address only, never by timing.

### 5.4 Limits

- Keep at most 500 connections. Evict the least recently active.
- Keep at most 200 packets per connection. Keep counting after the cap, and
  never drop the first 20, so handshakes survive.

### 5.5 UI

- The Bubble Tea model owns the store. Only `Update` mutates it, so no locks.
- A `tea.Cmd` blocks on a feed's channel and returns the next packet (or
  row) as a message. `Update` handles it and issues the same command again.
- Under very heavy traffic, refreshing the list on every packet gets
  expensive. If the UI lags, refresh the list on a timer instead and only
  call `AddPacket` per packet.
- Never print to stdout while the program runs. Debug with `tea.LogToFile`.

## 6. Screens

The main screen is one table of connections. Apps, protocols and hosts are
filters on that table, not separate panes.

### 6.1 Connections (main screen)

    Connections  312 shown of 480   filters: app=Safari  proto=TLSv1.3        LIVE
    TIME      APP           REMOTE                   PROTO    STATE    PKTS   BYTES   DUR
    14:02:11  Safari        github.com:443           TLSv1.3  open      307   275 KB  15.8s
    14:02:09  Safari+Slack  cdn.jsdelivr.net:443     TLSv1.3  open        8   3.9 KB   0.1s
    14:01:58  curl          example.com:443          TLSv1.3  reset       5    861 B   0.2s
    14:01:20  -             203.0.113.9:8443         TCP      midstream   2    276 B   0.0s

- One row per connection, from `store.Connections()`, newest first.
- One end of every connection is this Mac, so only the remote end is shown.
- TIME is the first packet, in local time. BYTES is the total of all packets
  in both directions. APP is `-` until Little Snitch has reported the address.
- The table is live: it is redrawn when a batch of data arrives (about ten
  times a second at most). Counts on existing rows grow and new connections
  appear at the top.
- The selection is remembered by connection key, not by row number, so the
  cursor stays on the same connection while rows are inserted above it.
- Only connections with packets seen since the program started are listed. A
  connection that was already running shows as `midstream`.

### 6.2 Packets (after Enter on a connection)

    github.com:443   TLSv1.3   Safari   closed   22 packets, 13.8 KB, 1.4s
    +TIME    DIR  PROTO    FLAGS      LEN   INFO
     0.000   ->   TCP      SYN         78   52311 -> 443 [SYN]
     0.021   <-   TCP      SYN, ACK    74   443 -> 52311 [SYN, ACK]
     0.022   ->   TCP      ACK         66   52311 -> 443 [ACK]
     0.024   ->   TLSv1.3  PSH, ACK   583   Client Hello (SNI=github.com)
     0.051   <-   TLSv1.3  PSH, ACK  1440   Server Hello, Change Cipher Spec, ...
     0.095   ->   TLSv1.3  PSH, ACK   420   Application Data

- One row per packet, from `store.Packets(key)`, oldest first. `->` is sent
  by this Mac, `<-` is received.
- +TIME is seconds since the connection's first packet.
- Packets are not strict request and response pairs; the arrows show the
  back and forth.
- When `Packets > Kept`, show one marker row after the first 20 packets saying
  how many are not kept.
- This view is live too while the connection is open.

### 6.3 Filters

Filters stack, and each active one is shown in the header.

| Key | Action |
|---|---|
| up/down, k/j | move the selection |
| enter | open the packets of the selected connection |
| esc | leave the packets view; on the main screen, remove the last filter |
| a | filter by the app of the selected row |
| p | filter by the protocol of the selected row |
| h | filter by the remote host of the selected row |
| / | filter by text typed, matched against app and remote |
| c | clear all filters |
| space | pause and resume redrawing (capture continues) |
| q, ctrl+c | quit and stop both child processes |

Mouse clicks on a cell can do the same as a, p and h later.

## 7. Command-line flags

| Flag | Default | Purpose |
|---|---|---|
| `--iface` | `en0` | capture interface |
| `--demo` | off | use `store.Demo()` and `store.DemoTick`, no sources started |
| `--replay <dir>` | off | read `littlesnitch.csv` and `tshark.tsv` from a directory, no root needed |
| `--littlesnitch <path>` | `littlesnitch` | path to the Little Snitch CLI |
| `--tshark <path>` | `tshark` | path to tshark |

On start, if a command is missing or not permitted, exit with a message that
says which one and how to fix it.

## 8. Milestones

Done: the data layer (`internal/source`, `internal/store`), with tests.

UI, built against `store.Demo()` first:

| # | Milestone | Done when |
|---|---|---|
| 1 | Connections table drawn from `store.Demo()` | all demo rows show, arrows move the selection, q quits |
| 2 | Packets view | Enter shows a connection's packets, Esc returns, the github.com handshake reads top to bottom |
| 3 | Filters | a, p, h, / and c work and stack; the header lists active filters |
| 4 | Live updates with `store.DemoTick` on a timer | counts grow, new rows appear, the selection stays on its connection, space pauses |
| 5 | Wire the real sources in `main.go`: flags, one command per feed that waits on its channel, `AddTraffic` and `AddPacket` in `Update` | real traffic shows when run with sudo; `--replay` works without |
| 6 | Record `testdata/littlesnitch.csv` and `testdata/tshark.tsv`; settle section 11 | both replay cleanly with zero skipped lines |
| 7 | Polish: column widths on resize, help bar, source errors shown in the UI, clean shutdown | survives a resize, leaves no child process behind |

## 9. Testing

- `go test ./...` covers both parsers, the feed and process handling, and the
  store: totals, every state transition, the join, limits and eviction.
- The tests use inline samples. Real recordings are added in milestone 6.
- `--demo` and `--replay` are the manual tests for the UI.

## 10. Later

- A per-app overview (bytes, hosts, blocked connections). The store already
  provides it: `Apps()`, `Hosts()`, `ConnectionsFor()`.
- Layer-by-layer breakdown of one packet.
- Highlight hosts an app has never contacted before.
- Export connections to CSV as input for the ML classifier.

## 11. Check before relying on

These were not confirmed on this machine when the spec was written:

- The table import path, expected to be `charm.land/bubbles/v2/table`, and the
  Lip Gloss v2 path, expected to be `charm.land/lipgloss/v2`. Confirm with
  `go get` or each repo's README.
- The tshark column field names. Newer versions may spell them
  `_ws.col.protocol` and `_ws.col.info`. Confirm with
  `tshark -G fields | grep _ws.col`.
- Where the `littlesnitch` binary lives and whether it is on `sudo`'s PATH.
- That `en0` is the active interface. List them with `tshark -D`.

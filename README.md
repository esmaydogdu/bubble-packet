# bubble-packet

See your Mac's network traffic live in the terminal: every connection, and the
packets inside it. Written in Go with Bubble Tea.

## Run

Needs two tools installed:

- [Wireshark](https://www.wireshark.org), for its `tshark` command
  (`brew install wireshark`). It supplies the packets.
- [Little Snitch](https://www.obdev.at/littlesnitch), with Settings > Security >
  "Allow access via Terminal" switched on. It supplies the app names.

Little Snitch only answers to root, so build and run with `sudo`:

    go build -o bubble-packet . && sudo ./bubble-packet

Without `sudo` or without Little Snitch the app still runs (`go run .`), but
the APP column stays empty.

## Keys

| Key | Action |
|---|---|
| up / down | move |
| enter | open a connection, then a packet |
| esc | go back |
| space | pause the list |
| q | quit |

## How it works

The app starts `tshark` and `littlesnitch`, reads what they print, groups the
packets into connections, and labels each connection with its app. See [SPEC.md](SPEC.md) for the design and what is planned next.

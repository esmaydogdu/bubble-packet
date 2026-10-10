// Package source holds the two data sources, littlesnitch and tshark, and
// the one helper they share.
package source

import "net/netip"

// NormIP returns one canonical spelling of an IP address, so that the two
// sources agree on it: IPv6 is compressed, IPv4-mapped IPv6 becomes IPv4, and
// any zone ("%en0") is dropped. Text that is not an address comes back as is.
func NormIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	return a.Unmap().WithZone("").String()
}

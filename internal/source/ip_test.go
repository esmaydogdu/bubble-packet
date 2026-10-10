package source

import "testing"

func TestNormIP(t *testing.T) {
	cases := map[string]string{
		"192.168.1.1": "192.168.1.1",
		"2A00:1450:400E:0811:0000:0000:0000:200E": "2a00:1450:400e:811::200e",
		"::ffff:192.168.1.1":                      "192.168.1.1",
		"fe80::1%en0":                             "fe80::1",
		"not-an-ip":                               "not-an-ip",
		"":                                        "",
	}
	for in, want := range cases {
		if got := NormIP(in); got != want {
			t.Errorf("NormIP(%q) = %q, want %q", in, got, want)
		}
	}
}

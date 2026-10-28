package profile

import "testing"

func TestSplitOverlayAddressesPicksEachFamily(t *testing.T) {
	for _, test := range []struct {
		in         []string
		ipv4, ipv6 string
	}{
		{[]string{"100.96.0.3", "fd48:5542:4e45::3"}, "100.96.0.3", "fd48:5542:4e45::3"},
		{[]string{"fd48:5542:4e45::3", "100.96.0.3"}, "100.96.0.3", "fd48:5542:4e45::3"},
		{[]string{"100.96.0.3"}, "100.96.0.3", ""},
		{nil, "", ""},
	} {
		ipv4, ipv6 := splitOverlayAddresses(test.in)
		if ipv4 != test.ipv4 || ipv6 != test.ipv6 {
			t.Errorf("%v -> %q %q", test.in, ipv4, ipv6)
		}
	}
}

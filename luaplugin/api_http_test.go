package luaplugin

import (
	"slices"
	"testing"
)

func TestSSRFGuardAllowedPrivateAddrs(t *testing.T) {
	t.Cleanup(func() { allowedPrivateAddrs.Store(nil) })

	cases := []struct {
		address string
		allowed map[string]bool
		ok      bool
	}{
		{"1.1.1.1:443", nil, true},
		{"127.0.0.1:8085", nil, false},
		{"192.168.1.20:8096", nil, false},
		{"127.0.0.1:8085", map[string]bool{"127.0.0.1:8085": true}, true},
		// only that exact address and port
		{"127.0.0.1:8086", map[string]bool{"127.0.0.1:8085": true}, false},
		{"192.168.1.20:8096", map[string]bool{"127.0.0.1:8085": true}, false},
		{"[::1]:8085", map[string]bool{"[::1]:8085": true}, true},
	}
	for _, c := range cases {
		if c.allowed == nil {
			allowedPrivateAddrs.Store(nil)
		} else {
			allowedPrivateAddrs.Store(&c.allowed)
		}
		err := ssrfGuard("tcp", c.address, nil)
		if (err == nil) != c.ok {
			t.Errorf("ssrfGuard(%s) with %v: err = %v, want allowed = %v", c.address, c.allowed, err, c.ok)
		}
	}
}

func TestResolveAllowedPrivateAddrs(t *testing.T) {
	cfg := map[string]map[string]string{"": {
		"allowed_private_addresses": "127.0.0.1:8085, [::1]:9000, 10.0.0.2:08080, 0:0:0:0:0:0:0:1:7000, localhost:80, 10.0.0.1, ,bad, 10.0.0.3:notaport, 10.0.0.4:0, 10.0.0.5:70000",
	}}
	allowed, invalid := resolveAllowedPrivateAddrs(cfg)

	// a zero-padded port is stored the way the dialer reports it
	want := map[string]bool{"127.0.0.1:8085": true, "[::1]:9000": true, "10.0.0.2:8080": true}
	if len(allowed) != len(want) {
		t.Fatalf("allowed = %v, want %v", allowed, want)
	}
	for addr := range want {
		if !allowed[addr] {
			t.Errorf("allowed is missing %s: %v", addr, allowed)
		}
	}
	// a host name, a missing or out-of-range port and junk are reported, never allowed;
	// an unbracketed IPv6 address with a port is ambiguous and reported too
	wantInvalid := []string{"0:0:0:0:0:0:0:1:7000", "localhost:80", "10.0.0.1", "bad", "10.0.0.3:notaport", "10.0.0.4:0", "10.0.0.5:70000"}
	if !slices.Equal(invalid, wantInvalid) {
		t.Errorf("invalid = %v, want %v", invalid, wantInvalid)
	}

	if allowed, invalid := resolveAllowedPrivateAddrs(nil); len(allowed) != 0 || len(invalid) != 0 {
		t.Errorf("nil config: allowed = %v, invalid = %v, want both empty", allowed, invalid)
	}
}

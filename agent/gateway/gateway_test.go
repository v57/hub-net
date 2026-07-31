package gateway

import (
	"net/netip"
	"testing"
)

func TestMemoryBackendEnableDisableTerminatesFlows(t *testing.T) {
	backend := &MemoryBackend{Flows: 3}
	config := DefaultConfig("hub123")
	if err := backend.Enable(config); err != nil {
		t.Fatal(err)
	}
	if !backend.Enabled || backend.Config.InterfaceName != "hub123" {
		t.Fatalf("enabled state = %#v", backend)
	}
	if err := backend.Disable(); err != nil {
		t.Fatal(err)
	}
	if backend.Enabled || backend.Flows != 0 {
		t.Fatalf("disabled state = %#v", backend)
	}
}

func TestDefaultConfigProtectsLocalAndPrivatePrefixes(t *testing.T) {
	config := DefaultConfig("hub123")
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1"} {
		address := netip.MustParseAddr(value)
		found := false
		for _, prefix := range config.ProtectedIPv4 {
			if prefix.Contains(address) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not protected", address)
		}
	}
}

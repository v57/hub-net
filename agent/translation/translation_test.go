package translation

import (
	"errors"
	"net/netip"
	"testing"
)

type fakeBackend struct {
	routes       []netip.Prefix
	installed    map[string]Allocation
	installError error
	removeError  error
}

func (f *fakeBackend) Routes() ([]netip.Prefix, error) {
	return append([]netip.Prefix(nil), f.routes...), nil
}
func (f *fakeBackend) Install(name string, allocation Allocation) error {
	if f.installError != nil {
		return f.installError
	}
	if f.installed == nil {
		f.installed = make(map[string]Allocation)
	}
	f.installed[name] = allocation
	return nil
}
func (f *fakeBackend) Remove(name string, _ Allocation) error {
	if f.removeError != nil {
		return f.removeError
	}
	delete(f.installed, name)
	return nil
}

func TestDistinctDeterministicAllocationsAndRestart(t *testing.T) {
	backend := &fakeBackend{}
	allocator, _ := NewAllocator(backend)
	first, err := allocator.Allocate("one", "", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := allocator.Allocate("two", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if first.IPv4 == second.IPv4 || first.IPv6 == second.IPv6 {
		t.Fatalf("overlapping allocations: %+v %+v", first, second)
	}
	restarted, _ := NewAllocator(backend)
	got, err := restarted.Allocate("one", first.IPv4.String(), first.IPv6.String())
	if err != nil || got != first {
		t.Fatalf("restart = %+v, %v; want %+v", got, err, first)
	}
}

func TestInterfaceNameStableAndCollisionSafe(t *testing.T) {
	first, err := InterfaceName("membership-one", nil)
	if err != nil || len(first) > 15 {
		t.Fatalf("name = %q, %v", first, err)
	}
	again, _ := InterfaceName("membership-one", map[string]string{first: "membership-one"})
	if again != first {
		t.Fatalf("idempotent name = %q, want %q", again, first)
	}
	second, err := InterfaceName("membership-one", map[string]string{first: "other"})
	if err != nil || second == first {
		t.Fatalf("collision name = %q, %v", second, err)
	}
}

func TestPersistedConflictFailsClosed(t *testing.T) {
	backend := &fakeBackend{}
	allocator, _ := NewAllocator(backend)
	allocation, _ := allocator.Allocate("one", "", "")
	restartedBackend := &fakeBackend{routes: []netip.Prefix{allocation.IPv4}}
	restarted, _ := NewAllocator(restartedBackend)
	if _, err := restarted.Allocate("one", allocation.IPv4.String(), allocation.IPv6.String()); !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

func TestNewAllocationLinearProbesAndExhausts(t *testing.T) {
	baseline := &fakeBackend{}
	firstAllocator, _ := NewAllocator(baseline)
	first, err := firstAllocator.Allocate("one", "", "")
	if err != nil {
		t.Fatal(err)
	}
	probing := &fakeBackend{routes: []netip.Prefix{first.IPv4}}
	secondAllocator, _ := NewAllocator(probing)
	second, err := secondAllocator.Allocate("one", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if second.IPv4 == first.IPv4 {
		t.Fatal("allocator did not probe past live conflict")
	}

	exhausted := &fakeBackend{}
	for _, prefix := range prefixSlots(IPv4Pool, CanonicalIPv4.Bits()) {
		exhausted.routes = append(exhausted.routes, prefix)
	}
	exhaustedAllocator, _ := NewAllocator(exhausted)
	if _, err := exhaustedAllocator.Allocate("one", "", ""); !errors.Is(err, ErrExhausted) {
		t.Fatalf("error = %v, want ErrExhausted", err)
	}
}

func TestReversibleTranslationPreservesHostBits(t *testing.T) {
	translated := netip.MustParsePrefix("10.32.0.0/11")
	canonical := CanonicalIPv4
	local := netip.MustParseAddr("10.33.2.3")
	remote, err := TranslateDestination(local, translated, canonical)
	if err != nil || remote.String() != "100.97.2.3" {
		t.Fatalf("canonical = %s, %v", remote, err)
	}
	back, err := TranslateSource(remote, canonical, translated)
	if err != nil || back != local {
		t.Fatalf("translated = %s, %v", back, err)
	}
}

func TestManagerRollbackAndSiblingCleanup(t *testing.T) {
	backend := &fakeBackend{}
	allocator, _ := NewAllocator(backend)
	manager, _ := NewManager(allocator, backend)
	one, err := manager.Activate("one", "hubnet0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate("two", "hubnet1", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := manager.Deactivate("one"); err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.installed["hubnet1"]; !ok {
		t.Fatal("sibling installation removed")
	}

	failing := &fakeBackend{installError: errors.New("install failed")}
	failingAllocator, _ := NewAllocator(failing)
	failingManager, _ := NewManager(failingAllocator, failing)
	if _, err := failingManager.Activate("one", "hubnet0", one.IPv4.String(), one.IPv6.String()); err == nil {
		t.Fatal("expected install failure")
	}
	failing.installError = nil
	if _, err := failingManager.Activate("one", "hubnet0", one.IPv4.String(), one.IPv6.String()); err != nil {
		t.Fatalf("claim leaked after rollback: %v", err)
	}
}

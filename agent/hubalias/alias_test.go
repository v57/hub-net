package hubalias

import "testing"

func TestNormalize(t *testing.T) {
	for input, want := range map[string]string{
		" Home Hub ":  "home-hub",
		"HUB.example": "hub-example",
		"---":         "hub",
	} {
		if got := Normalize(input); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAllocateSequence(t *testing.T) {
	if got := Allocate("Hub", []string{"hub", "hub-2"}); got != "hub-3" {
		t.Fatalf("Allocate Hub = %q, want hub-3", got)
	}
	if got := Allocate("Hub-1", []string{"hub-1"}); got != "hub-2" {
		t.Fatalf("Allocate Hub-1 = %q, want hub-2", got)
	}
	if got := Allocate("Hub-1", []string{"hub-1", "hub-2"}); got != "hub-3" {
		t.Fatalf("Allocate duplicate Hub-1 = %q, want hub-3", got)
	}
}

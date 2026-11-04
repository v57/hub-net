package deviceports

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAMissingFileIsAnEmptyListWithSSHOff(t *testing.T) {
	list, err := Open(filepath.Join(t.TempDir(), "device-ports.json"))
	if err != nil {
		t.Fatal(err)
	}
	if list.Allows(Port{"tcp", 22}, nil) {
		t.Fatal("SSH opened without being enabled")
	}
	if list.Allows(Port{"tcp", 8080}, nil) {
		t.Fatal("a port nobody allowed opened")
	}
}

func TestSharesAndAllowedPortsOpenOthersDont(t *testing.T) {
	list, err := Open(filepath.Join(t.TempDir(), "device-ports.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Allow(Port{"udp", 5000}); err != nil {
		t.Fatal(err)
	}
	shares := []Port{{"tcp", 8080}}
	got := list.Filter([]Port{{"tcp", 8080}, {"udp", 5000}, {"tcp", 22}, {"tcp", 9000}}, shares)
	if len(got) != 2 || got[0] != (Port{"tcp", 8080}) || got[1] != (Port{"udp", 5000}) {
		t.Fatalf("Filter = %+v", got)
	}
	if err := list.Remove(Port{"udp", 5000}); err != nil {
		t.Fatal(err)
	}
	if list.Allows(Port{"udp", 5000}, nil) {
		t.Fatal("a removed port stayed open")
	}
}

func TestAttestationsDontTurnOnSSH(t *testing.T) {
	list, err := Open(filepath.Join(t.TempDir(), "device-ports.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := list.NoteAttested(Port{"tcp", 22}); err != nil {
		t.Fatal(err)
	}
	if list.Allows(Port{"tcp", 22}, nil) {
		t.Fatal("an attestation opened the SSH port")
	}
	if err := list.SetSSH(true, 0); err != nil {
		t.Fatal(err)
	}
	if !list.Allows(Port{"tcp", 22}, nil) {
		t.Fatal("SSH stayed closed after being enabled")
	}
	if err := list.SetSSH(false, 0); err != nil {
		t.Fatal(err)
	}
	if err := list.SetSSH(true, 2222); err != nil {
		t.Fatal(err)
	}
	if !list.Allows(Port{"tcp", 2222}, nil) {
		t.Fatal("the chosen SSH port stayed closed")
	}
}

func TestAttestedPortsLastUntilTheyAgeOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-ports.json")
	list, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	list.SetNowForTest(func() time.Time { return now })
	if err := list.NoteAttested(Port{"tcp", 8554}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.SetNowForTest(func() time.Time { return now.Add(time.Hour) })
	if !reopened.Allows(Port{"tcp", 8554}, nil) {
		t.Fatal("a restart closed an attested port")
	}
	reopened.SetNowForTest(func() time.Time { return now.Add(AttestedLifetime + time.Hour) })
	if reopened.Allows(Port{"tcp", 8554}, nil) {
		t.Fatal("an attested port outlived its lifetime")
	}
}

func TestACorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-ports.json")
	if _, err := Command(path, []string{"allow", "tcp/8080"}); err != nil {
		t.Fatal(err)
	}
	if output, err := Command(path, []string{"list"}); err != nil || output != "ssh off (tcp/22)\nallowed tcp/8080" {
		t.Fatalf("list = %q, %v", output, err)
	}
	if _, err := Command(path, []string{"allow", "ssh"}); err == nil {
		t.Fatal("a bad port was taken")
	}
}

func TestReloadSeesAnotherProcessEditing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-ports.json")
	list, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := list.Reload(); err != nil || changed {
		t.Fatalf("Reload with no file = %v, %v", changed, err)
	}
	if _, err := Command(path, []string{"ssh", "on"}); err != nil {
		t.Fatal(err)
	}
	if changed, err := list.Reload(); err != nil || !changed {
		t.Fatalf("Reload after an edit = %v, %v", changed, err)
	}
	if !list.Allows(Port{"tcp", 22}, nil) {
		t.Fatal("the running list didn't take the edit")
	}
}

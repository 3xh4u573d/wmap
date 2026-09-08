package query

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/3xh4u573d/wmap/internal/model"
	"github.com/3xh4u573d/wmap/internal/parse"
)

func mustLoad(t *testing.T, name string) model.Scan {
	t.Helper()
	s, err := parse.File(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func run(t *testing.T, scan model.Scan, f Filter, sc Shortcuts) []Match {
	t.Helper()
	f.ApplyShortcuts(sc)
	if err := f.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return Run([]model.Scan{scan}, f)
}

func TestShortcutSMB(t *testing.T) {
	m := run(t, mustLoad(t, "scan_b.xml"), Filter{}, Shortcuts{SMB: true})
	got := Targets(m)
	want := []string{"10.0.0.20:445"}
	if !equal(got, want) {
		t.Fatalf("--smb targets = %v, want %v", got, want)
	}
}

func TestShortcutWeb(t *testing.T) {
	m := run(t, mustLoad(t, "scan_b.xml"), Filter{}, Shortcuts{Web: true})
	got := Targets(m)
	sort.Strings(got)
	want := []string{"10.0.0.5:443", "10.0.0.5:80"}
	if !equal(got, want) {
		t.Fatalf("--web targets = %v, want %v", got, want)
	}
}

func TestShortcutVuln(t *testing.T) {
	m := run(t, mustLoad(t, "scan_b.xml"), Filter{}, Shortcuts{Vuln: true})
	if got := Targets(m); !equal(got, []string{"10.0.0.5:443"}) {
		t.Fatalf("--vuln targets = %v, want [10.0.0.5:443]", got)
	}
}

func TestStateFilter(t *testing.T) {
	m := run(t, mustLoad(t, "scan_b.xml"),
		Filter{PortSpecs: []string{"3306"}, States: []string{"filtered"}}, Shortcuts{})
	if got := Targets(m); !equal(got, []string{"10.0.0.10:3306"}) {
		t.Fatalf("filtered 3306 = %v", got)
	}
}

func TestOSFilter(t *testing.T) {
	m := run(t, mustLoad(t, "scan_b.xml"), Filter{OS: []string{"windows"}}, Shortcuts{})
	if got := Hosts(m); !equal(got, []string{"10.0.0.20"}) {
		t.Fatalf("--os windows hosts = %v", got)
	}
}

func TestScriptFilter(t *testing.T) {
	m := run(t, mustLoad(t, "scan_a.xml"), Filter{Scripts: []string{"ftp-anon"}}, Shortcuts{})
	if got := Targets(m); !equal(got, []string{"10.0.0.15:21"}) {
		t.Fatalf("--script ftp-anon = %v", got)
	}
}

func TestPortRange(t *testing.T) {
	m := run(t, mustLoad(t, "scan_b.xml"),
		Filter{PortSpecs: []string{"85-390"}}, Shortcuts{})
	got := Targets(m)
	sort.Strings(got)
	want := []string{"10.0.0.20:389", "10.0.0.20:88"}
	if !equal(got, want) {
		t.Fatalf("ports 85-390 = %v, want %v", got, want)
	}
}

func TestBadPortSpec(t *testing.T) {
	f := Filter{PortSpecs: []string{"nope"}}
	if err := f.Compile(); err == nil {
		t.Fatal("expected error for bad port spec")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

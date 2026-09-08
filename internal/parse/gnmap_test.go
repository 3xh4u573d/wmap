package parse

import (
	"path/filepath"
	"testing"
)

func TestGnmap(t *testing.T) {
	s, err := File(filepath.Join("..", "..", "testdata", "scan_a.gnmap"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s.UpHosts()); got != 3 {
		t.Fatalf("up hosts = %d, want 3", got)
	}
	web, ok := s.Host("10.0.0.5")
	if !ok {
		t.Fatal("10.0.0.5 missing")
	}
	if web.Name() != "web-01.lab.local" {
		t.Errorf("hostname = %q", web.Name())
	}
	p80, ok := portByID(web.Ports, 80)
	if !ok || !p80.IsOpen() {
		t.Fatalf("tcp/80 = %+v (found=%v)", p80, ok)
	}
	if p80.Service == nil || p80.Service.Name != "http" {
		t.Errorf("tcp/80 service = %+v", p80.Service)
	}
	if got := p80.Service.Banner(); got != "nginx 1.18.0" {
		t.Errorf("tcp/80 banner = %q, want %q", got, "nginx 1.18.0")
	}
}

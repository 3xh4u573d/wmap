package parse

import (
	"path/filepath"
	"testing"

	"github.com/3xh4u573d/wmap/internal/model"
)

func portByID(ports []model.Port, id int) (model.Port, bool) {
	for _, p := range ports {
		if p.ID == id {
			return p, true
		}
	}
	return model.Port{}, false
}

func hasScript(scripts []model.Script, id string) bool {
	for _, s := range scripts {
		if s.ID == id {
			return true
		}
	}
	return false
}

func TestXMLScanB(t *testing.T) {
	s, err := File(filepath.Join("..", "..", "testdata", "scan_b.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s.UpHosts()); got != 3 {
		t.Fatalf("up hosts = %d, want 3", got)
	}
	if s.Args == "" {
		t.Error("scan args not parsed")
	}

	dc, ok := s.Host("10.0.0.20")
	if !ok {
		t.Fatal("10.0.0.20 not found")
	}
	if got := len(dc.OpenPorts()); got != 4 {
		t.Errorf("dc-01 open ports = %d, want 4", got)
	}
	if om, ok := dc.BestOS(); !ok || om.Name != "Microsoft Windows Server 2019" {
		t.Errorf("dc-01 OS match = %+v (ok=%v)", om, ok)
	}
	if !hasScript(dc.HostScripts, "smb-os-discovery") {
		t.Errorf("dc-01 host scripts = %+v", dc.HostScripts)
	}

	web, _ := s.Host("10.0.0.5")
	p443, ok := portByID(web.Ports, 443)
	if !ok {
		t.Fatal("web-01 tcp/443 missing")
	}
	if p443.Service == nil || p443.Service.Tunnel != "ssl" {
		t.Errorf("tcp/443 service = %+v", p443.Service)
	}
	if !hasScript(p443.Scripts, "ssl-poodle") {
		t.Error("tcp/443 ssl-poodle script missing")
	}

	db, _ := s.Host("10.0.0.10")
	p3306, ok := portByID(db.Ports, 3306)
	if !ok || p3306.State != "filtered" {
		t.Errorf("db-01 tcp/3306 = %q (found=%v), want filtered", p3306.State, ok)
	}
}

func TestXMLRejectsNonNmap(t *testing.T) {
	if _, err := XML([]byte(`<foo/>`), "x.xml"); err == nil {
		t.Fatal("expected error for non-nmap xml")
	}
}

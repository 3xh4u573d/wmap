package diff

import (
	"path/filepath"
	"testing"

	"github.com/3xh4u573d/wmap/internal/model"
	"github.com/3xh4u573d/wmap/internal/parse"
)

func load(t *testing.T, name string) model.Scan {
	t.Helper()
	s, err := parse.File(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestComputeAB(t *testing.T) {
	a := load(t, "scan_a.xml")
	b := load(t, "scan_b.xml")
	d := Compute(a, b)

	if d.Empty() {
		t.Fatal("expected changes")
	}
	if len(d.Added) != 1 || d.Added[0].IP() != "10.0.0.20" {
		t.Errorf("added = %v", ips(d.Added))
	}
	if len(d.Removed) != 1 || d.Removed[0].IP() != "10.0.0.15" {
		t.Errorf("removed = %v", ips(d.Removed))
	}

	web := changedHost(d, "10.0.0.5")
	if web == nil {
		t.Fatal("10.0.0.5 not in changed set")
	}
	if len(web.Opened) != 1 || web.Opened[0].ID != 443 {
		t.Errorf("web opened = %+v", web.Opened)
	}
	if len(web.Services) != 1 || web.Services[0].Port != 22 {
		t.Errorf("web service changes = %+v", web.Services)
	}

	db := changedHost(d, "10.0.0.10")
	if db == nil || len(db.Closed) != 1 || db.Closed[0].ID != 3306 {
		t.Errorf("db closed = %+v", db)
	}
}

func TestComputeIdentity(t *testing.T) {
	a := load(t, "scan_a.xml")
	if !Compute(a, a).Empty() {
		t.Fatal("scan diffed against itself should be empty")
	}
}

func changedHost(d Diff, ip string) *HostDiff {
	for i := range d.Changed {
		if d.Changed[i].IP == ip {
			return &d.Changed[i]
		}
	}
	return nil
}

func ips(hs []model.Host) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.IP())
	}
	return out
}

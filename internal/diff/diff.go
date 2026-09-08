package diff

import (
	"path/filepath"
	"sort"

	"github.com/3xh4u573d/wmap/internal/model"
)

type ServiceChange struct {
	Port   int
	Proto  string
	Before string
	After  string
}

type HostDiff struct {
	IP       string
	Label    string
	Opened   []model.Port
	Closed   []model.Port
	Services []ServiceChange
}

func (h HostDiff) Empty() bool {
	return len(h.Opened) == 0 && len(h.Closed) == 0 && len(h.Services) == 0
}

type Diff struct {
	OldLabel string
	NewLabel string
	Added    []model.Host
	Removed  []model.Host
	Changed  []HostDiff
}

func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

func Compute(old, new model.Scan) Diff {
	d := Diff{OldLabel: label(old), NewLabel: label(new)}
	oldHosts := indexHosts(old)
	newHosts := indexHosts(new)

	for ip, nh := range newHosts {
		if _, ok := oldHosts[ip]; !ok {
			d.Added = append(d.Added, nh)
		}
	}
	for ip, oh := range oldHosts {
		if _, ok := newHosts[ip]; !ok {
			d.Removed = append(d.Removed, oh)
		}
	}
	for ip, oh := range oldHosts {
		nh, ok := newHosts[ip]
		if !ok {
			continue
		}
		hd := HostDiff{IP: ip, Label: nh.Label()}
		oldPorts := indexPorts(oh)
		newPorts := indexPorts(nh)

		for key, np := range newPorts {
			if op, ok := oldPorts[key]; (!ok || !op.IsOpen()) && np.IsOpen() {
				hd.Opened = append(hd.Opened, np)
			}
		}
		for key, op := range oldPorts {
			if !op.IsOpen() {
				continue
			}
			if np, ok := newPorts[key]; !ok || !np.IsOpen() {
				hd.Closed = append(hd.Closed, op)
			}
		}
		for key, np := range newPorts {
			op, ok := oldPorts[key]
			if !ok || !op.IsOpen() || !np.IsOpen() {
				continue
			}
			before, after := op.Service.Banner(), np.Service.Banner()
			if before != after {
				hd.Services = append(hd.Services, ServiceChange{
					Port:   np.ID,
					Proto:  np.Protocol,
					Before: before,
					After:  after,
				})
			}
		}

		model.SortPorts(hd.Opened)
		model.SortPorts(hd.Closed)
		sort.Slice(hd.Services, func(i, j int) bool { return hd.Services[i].Port < hd.Services[j].Port })
		if !hd.Empty() {
			d.Changed = append(d.Changed, hd)
		}
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].IP() < d.Added[j].IP() })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].IP() < d.Removed[j].IP() })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].IP < d.Changed[j].IP })
	return d
}

func indexHosts(s model.Scan) map[string]model.Host {
	m := map[string]model.Host{}
	for _, h := range s.Hosts {
		if h.Up {
			if ip := h.IP(); ip != "" {
				m[ip] = h
			}
		}
	}
	return m
}

func indexPorts(h model.Host) map[string]model.Port {
	m := map[string]model.Port{}
	for _, p := range h.Ports {
		m[p.Key()] = p
	}
	return m
}

func label(s model.Scan) string {
	if s.Source == "" {
		return "scan"
	}
	return filepath.Base(s.Source)
}

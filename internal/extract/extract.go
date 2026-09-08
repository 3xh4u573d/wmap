package extract

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/3xh4u573d/wmap/internal/diff"
	"github.com/3xh4u573d/wmap/internal/model"
)

type Mode int

const (
	ModeHosts Mode = iota
	ModeURLs
	ModeHTTPURLs
	ModeURLsAll
	ModeChanges
)

type Options struct {
	Mode     Mode
	Ports    []int
	Open     bool
	Filtered bool
	Names    bool
	Verbose  bool
	Diff     bool
}

func (o Options) portOK(id int) bool {
	if len(o.Ports) == 0 {
		return true
	}
	for _, p := range o.Ports {
		if p == id {
			return true
		}
	}
	return false
}

func (o Options) stateOK(p model.Port) bool {
	st := strings.ToLower(p.State)
	isOpen := strings.HasPrefix(st, "open")
	isFilt := strings.Contains(st, "filtered")
	wantOpen := o.Open || (!o.Open && !o.Filtered)
	return (wantOpen && isOpen) || (o.Filtered && isFilt)
}

type line struct {
	value string
	note  string
	force bool
}

func Run(scans []model.Scan, opt Options) []string {
	var lines []line
	if opt.Diff && len(scans) == 2 {
		lines = runDiff(scans[0], scans[1], opt)
	} else {
		lines = runSingle(scans, opt)
	}

	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l.note != "" && (opt.Verbose || l.force) {
			out = append(out, l.value+"\t# "+l.note)
		} else {
			out = append(out, l.value)
		}
	}
	return out
}

func runSingle(scans []model.Scan, opt Options) []line {
	var out []line
	seen := map[string]struct{}{}
	add := func(value, note string) {
		if value == "" {
			return
		}
		if _, dup := seen[value]; dup {
			return
		}
		seen[value] = struct{}{}
		out = append(out, line{value: value, note: note})
	}

	for si := range scans {
		for _, h := range scans[si].Hosts {
			if !h.Up {
				continue
			}
			host := hostLabel(h, opt.Names)
			if host == "" {
				continue
			}
			ports := matchingPorts(h, opt)
			if len(ports) == 0 {
				continue
			}

			switch opt.Mode {
			case ModeHosts:
				add(host, noteHost(h, ports))
			case ModeURLs:
				for _, p := range ports {
					add(serviceURL(host, p), notePort(p))
				}
			case ModeHTTPURLs:
				for _, p := range ports {
					add(webURL(host, p), notePort(p))
				}
			case ModeURLsAll:
				hp := urlHost(host)
				for _, p := range ports {
					add("http://"+hp+portSuffix(p.ID, 80), notePort(p))
				}
				for _, p := range ports {
					add("https://"+hp+portSuffix(p.ID, 443), notePort(p))
				}
			}
		}
	}
	return out
}

func matchingPorts(h model.Host, opt Options) []model.Port {
	var ports []model.Port
	for _, p := range h.Ports {
		if !opt.portOK(p.ID) || !opt.stateOK(p) {
			continue
		}
		if opt.Mode != ModeHosts && opt.Mode != ModeChanges && p.Protocol != "tcp" {
			continue
		}
		ports = append(ports, p)
	}
	model.SortPorts(ports)
	return ports
}

func runDiff(old, new model.Scan, opt Options) []line {
	if opt.Mode == ModeChanges {
		return changeLines(old, new, opt)
	}
	oldLines := runSingle([]model.Scan{old}, opt)
	newLines := runSingle([]model.Scan{new}, opt)
	oldSet, newSet := valueSet(oldLines), valueSet(newLines)

	var out []line
	for _, l := range newLines {
		if _, had := oldSet[l.value]; !had {
			out = append(out, line{value: "+" + l.value, note: l.note})
		}
	}
	for _, l := range oldLines {
		if _, still := newSet[l.value]; !still {
			out = append(out, line{value: "-" + l.value, note: l.note})
		}
	}
	return out
}

func changeLines(old, new model.Scan, opt Options) []line {
	d := diff.Compute(old, new)
	var out []line
	push := func(sign, host string, p model.Port) {
		if !opt.portOK(p.ID) {
			return
		}
		out = append(out, line{value: sign + host + ":" + strconv.Itoa(p.ID), note: notePort(p), force: false})
	}

	for _, h := range d.Added {
		host := hostLabel(h, opt.Names)
		for _, p := range h.OpenPorts() {
			push("+", host, p)
		}
	}
	for _, h := range d.Removed {
		host := hostLabel(h, opt.Names)
		for _, p := range h.OpenPorts() {
			push("-", host, p)
		}
	}
	for _, hc := range d.Changed {
		host := hc.IP
		for _, p := range hc.Opened {
			push("+", host, p)
		}
		for _, p := range hc.Closed {
			push("-", host, p)
		}
		for _, sc := range hc.Services {
			if !opt.portOK(sc.Port) {
				continue
			}
			out = append(out, line{
				value: "~" + host + ":" + strconv.Itoa(sc.Port),
				note:  orNone(sc.Before) + " -> " + orNone(sc.After),
				force: true,
			})
		}
	}
	return out
}

func valueSet(ls []line) map[string]struct{} {
	m := make(map[string]struct{}, len(ls))
	for _, l := range ls {
		m[l.value] = struct{}{}
	}
	return m
}

func hostLabel(h model.Host, names bool) string {
	if names {
		if n := h.Name(); n != "" {
			return n
		}
	}
	return h.IP()
}

func urlHost(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

func portSuffix(id, def int) string {
	if id == def {
		return ""
	}
	return ":" + strconv.Itoa(id)
}

func serviceURL(host string, p model.Port) string {
	name, tunnel := serviceHints(p)
	scheme, def := schemeForService(name, tunnel)
	if scheme == "" {
		return ""
	}
	return scheme + "://" + urlHost(host) + portSuffix(p.ID, def)
}

func webURL(host string, p model.Port) string {
	name, tunnel := serviceHints(p)
	ssl := tunnel == "ssl" || tunnel == "tls" || strings.Contains(name, "ssl") || strings.Contains(name, "tls")

	scheme := ""
	switch {
	case strings.Contains(name, "https"):
		scheme = "https"
	case strings.HasPrefix(name, "http") || name == "www" || name == "http-alt" || name == "http-proxy" || name == "http-mgmt" || name == "caldav" || name == "webcache":
		if ssl {
			scheme = "https"
		} else {
			scheme = "http"
		}
	case name == "sip-tls" || (ssl && name == ""):
		scheme = "https"
	}

	if scheme == "" {
		probed := p.Service != nil && p.Service.Method == "probed"
		vague := name == "" || name == "unknown" || name == "tcpwrapped"
		if !probed || vague {
			switch {
			case httpsPorts[p.ID]:
				scheme = "https"
			case httpPorts[p.ID]:
				scheme = "http"
			}
		}
	}
	if scheme == "" {
		return ""
	}
	def := 80
	if scheme == "https" {
		def = 443
	}
	return scheme + "://" + urlHost(host) + portSuffix(p.ID, def)
}

func serviceHints(p model.Port) (name, tunnel string) {
	if p.Service == nil {
		return "", ""
	}
	return strings.ToLower(strings.TrimSpace(p.Service.Name)),
		strings.ToLower(strings.TrimSpace(p.Service.Tunnel))
}

func noteHost(h model.Host, ports []model.Port) string {
	var parts []string
	if n := h.Name(); n != "" && n != h.IP() {
		parts = append(parts, n)
	}
	ids := make([]string, 0, len(ports))
	for i, p := range ports {
		if i == 10 {
			ids = append(ids, "...")
			break
		}
		ids = append(ids, strconv.Itoa(p.ID))
	}
	parts = append(parts, fmt.Sprintf("%d ports (%s)", len(ports), strings.Join(ids, ", ")))
	if om, ok := h.BestOS(); ok {
		parts = append(parts, om.Name)
	}
	return strings.Join(parts, " · ")
}

func notePort(p model.Port) string {
	s := fmt.Sprintf("%d/%s", p.ID, p.Protocol)
	if p.Service != nil {
		if l := p.Service.Label(); l != "" {
			s += " " + l
		}
		if b := p.Service.Banner(); b != "" {
			s += " " + b
		}
	}
	if !p.IsOpen() {
		s += " [" + p.State + "]"
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

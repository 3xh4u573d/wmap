package query

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/3xh4u573d/wmap/internal/model"
)

type Filter struct {
	HostSpecs []string
	PortSpecs []string
	States    []string
	Services  []string
	Products  []string
	Versions  []string
	CPEs      []string
	Scripts   []string
	OS        []string

	cidrs      []*net.IPNet
	hostSubs   []string
	ports      map[int]bool
	portRanges [][2]int
	states     map[string]bool
}

type Shortcuts struct {
	Web, SMB, RDP, SSH, DB, Vuln bool
}

func (f *Filter) ApplyShortcuts(s Shortcuts) {
	if s.Web {
		f.Services = append(f.Services, "http")
	}
	if s.SMB {
		f.Services = append(f.Services, "microsoft-ds", "netbios-ssn", "smb")
	}
	if s.RDP {
		f.Services = append(f.Services, "ms-wbt-server", "rdp")
	}
	if s.SSH {
		f.Services = append(f.Services, "ssh")
	}
	if s.DB {
		f.Services = append(f.Services,
			"ms-sql", "mysql", "postgresql", "oracle", "mongod",
			"redis", "cassandra", "memcached", "couchdb", "elasticsearch")
	}
	if s.Vuln {
		f.Scripts = append(f.Scripts, "vuln", "VULNERABLE")
	}
}

func (f *Filter) Compile() error {
	f.states = map[string]bool{}
	for _, s := range f.States {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			f.states[s] = true
		}
	}
	if len(f.states) == 0 {
		f.states["open"] = true
	}

	f.ports = map[int]bool{}
	for _, spec := range f.PortSpecs {
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if lo, hi, isRange := strings.Cut(part, "-"); isRange {
				a, err1 := strconv.Atoi(strings.TrimSpace(lo))
				b, err2 := strconv.Atoi(strings.TrimSpace(hi))
				if err1 != nil || err2 != nil || a > b {
					return fmt.Errorf("bad port range %q", part)
				}
				f.portRanges = append(f.portRanges, [2]int{a, b})
			} else {
				n, err := strconv.Atoi(part)
				if err != nil {
					return fmt.Errorf("bad port %q", part)
				}
				f.ports[n] = true
			}
		}
	}

	for _, hs := range f.HostSpecs {
		hs = strings.TrimSpace(hs)
		if hs == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(hs); err == nil {
			f.cidrs = append(f.cidrs, ipnet)
		} else {
			f.hostSubs = append(f.hostSubs, strings.ToLower(hs))
		}
	}
	return nil
}

type Match struct {
	Scan *model.Scan
	Host model.Host
	Port model.Port
}

func Run(scans []model.Scan, f Filter) []Match {
	var out []Match
	for i := range scans {
		s := &scans[i]
		for _, h := range s.Hosts {
			if !h.Up || !f.matchHost(h) || !f.matchOS(h) {
				continue
			}
			for _, p := range h.SortedPorts() {
				if f.matchState(p) && f.matchPort(p) && f.matchService(p) && f.matchScript(h, p) {
					out = append(out, Match{Scan: s, Host: h, Port: p})
				}
			}
		}
	}
	return out
}

func (f *Filter) matchHost(h model.Host) bool {
	if len(f.cidrs) == 0 && len(f.hostSubs) == 0 {
		return true
	}
	var addrs []string
	for _, a := range h.Addresses {
		addrs = append(addrs, a)
	}
	for _, c := range f.cidrs {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && c.Contains(ip) {
				return true
			}
		}
	}
	hay := strings.ToLower(strings.Join(append(addrs, h.Hostnames...), " "))
	for _, sub := range f.hostSubs {
		if strings.Contains(hay, sub) {
			return true
		}
	}
	return false
}

func (f *Filter) matchState(p model.Port) bool {
	st := strings.ToLower(p.State)
	if f.states[st] {
		return true
	}
	if f.states["open"] && p.IsOpen() {
		return true
	}
	if f.states["filtered"] && strings.Contains(st, "filtered") {
		return true
	}
	return false
}

func (f *Filter) matchPort(p model.Port) bool {
	if len(f.ports) == 0 && len(f.portRanges) == 0 {
		return true
	}
	if f.ports[p.ID] {
		return true
	}
	for _, r := range f.portRanges {
		if p.ID >= r[0] && p.ID <= r[1] {
			return true
		}
	}
	return false
}

func (f *Filter) matchService(p model.Port) bool {
	if len(f.Services) == 0 && len(f.Products) == 0 && len(f.Versions) == 0 && len(f.CPEs) == 0 {
		return true
	}
	var name, product, version, cpe string
	if p.Service != nil {
		name = p.Service.Label()
		product = p.Service.Product
		version = p.Service.Version
		cpe = strings.Join(p.Service.CPEs, " ")
	}
	return anyContains(f.Services, name) &&
		anyContains(f.Products, product) &&
		anyContains(f.Versions, version) &&
		anyContains(f.CPEs, cpe)
}

func (f *Filter) matchScript(h model.Host, p model.Port) bool {
	if len(f.Scripts) == 0 {
		return true
	}
	scripts := append([]model.Script(nil), p.Scripts...)
	scripts = append(scripts, h.HostScripts...)
	for _, want := range f.Scripts {
		want = strings.ToLower(want)
		hit := false
		for _, s := range scripts {
			if strings.Contains(strings.ToLower(s.ID), want) ||
				strings.Contains(strings.ToLower(s.Output), want) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func (f *Filter) matchOS(h model.Host) bool {
	if len(f.OS) == 0 {
		return true
	}
	var names []string
	for _, m := range h.OSMatches {
		names = append(names, m.Name)
	}
	return anyContains(f.OS, strings.Join(names, " "))
}

func anyContains(subs []string, val string) bool {
	if len(subs) == 0 {
		return true
	}
	val = strings.ToLower(val)
	for _, s := range subs {
		if strings.Contains(val, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func Hosts(matches []Match) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		ip := m.Host.IP()
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

func Targets(matches []Match) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		t := fmt.Sprintf("%s:%d", m.Host.IP(), m.Port.ID)
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

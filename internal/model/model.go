package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Service struct {
	Name       string
	Product    string
	Version    string
	ExtraInfo  string
	OSType     string
	DeviceType string
	Hostname   string
	Method     string
	Conf       int
	Tunnel     string
	CPEs       []string
}

func (s *Service) Banner() string {
	if s == nil {
		return ""
	}
	var parts []string
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	out := strings.Join(parts, " ")
	if s.ExtraInfo != "" {
		if out != "" {
			out += " "
		}
		out += "(" + s.ExtraInfo + ")"
	}
	return out
}

func (s *Service) Label() string {
	if s == nil || s.Name == "" {
		return ""
	}
	if s.Tunnel != "" {
		return s.Tunnel + "/" + s.Name
	}
	return s.Name
}

type Script struct {
	ID     string
	Output string
}

type Port struct {
	Protocol string
	ID       int
	State    string
	Reason   string
	Service  *Service
	Scripts  []Script
}

func (p Port) IsOpen() bool { return strings.HasPrefix(p.State, "open") }

func (p Port) Key() string { return fmt.Sprintf("%s/%d", p.Protocol, p.ID) }

type OSMatch struct {
	Name     string
	Accuracy int
	CPEs     []string
}

type Host struct {
	Up          bool
	StateReason string
	Addresses   map[string]string
	Vendor      string
	Hostnames   []string
	Ports       []Port
	OSMatches   []OSMatch
	HostScripts []Script
	StartTime   time.Time
	EndTime     time.Time
	Distance    int
}

func (h Host) IP() string {
	for _, k := range []string{"ipv4", "ipv6", "mac"} {
		if v := h.Addresses[k]; v != "" {
			return v
		}
	}
	return ""
}

func (h Host) Name() string {
	if len(h.Hostnames) > 0 {
		return h.Hostnames[0]
	}
	return ""
}

func (h Host) Label() string {
	if n := h.Name(); n != "" {
		return fmt.Sprintf("%s (%s)", h.IP(), n)
	}
	return h.IP()
}

func (h Host) OpenPorts() []Port {
	var out []Port
	for _, p := range h.Ports {
		if p.IsOpen() {
			out = append(out, p)
		}
	}
	SortPorts(out)
	return out
}

func (h Host) SortedPorts() []Port {
	out := append([]Port(nil), h.Ports...)
	SortPorts(out)
	return out
}

func (h Host) BestOS() (OSMatch, bool) {
	if len(h.OSMatches) == 0 {
		return OSMatch{}, false
	}
	best := h.OSMatches[0]
	for _, m := range h.OSMatches[1:] {
		if m.Accuracy > best.Accuracy {
			best = m
		}
	}
	return best, true
}

func (h Host) AllScripts() []Script {
	out := append([]Script(nil), h.HostScripts...)
	for _, p := range h.Ports {
		out = append(out, p.Scripts...)
	}
	return out
}

func SortPorts(ports []Port) {
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		return ports[i].ID < ports[j].ID
	})
}

type Scan struct {
	Scanner    string
	Args       string
	Version    string
	Start      time.Time
	End        time.Time
	Elapsed    float64
	ScanTypes  []string
	Hosts      []Host
	Source     string
	Partial    bool
	ExitStatus string
}

func (s Scan) UpHosts() []Host {
	var out []Host
	for _, h := range s.Hosts {
		if h.Up {
			out = append(out, h)
		}
	}
	return out
}

func (s Scan) DownHosts() []Host {
	var out []Host
	for _, h := range s.Hosts {
		if !h.Up {
			out = append(out, h)
		}
	}
	return out
}

func (s Scan) Host(addr string) (Host, bool) {
	for _, h := range s.Hosts {
		for _, a := range h.Addresses {
			if a == addr {
				return h, true
			}
		}
	}
	return Host{}, false
}

func (s Scan) CountOpenPorts() int {
	n := 0
	for _, h := range s.Hosts {
		n += len(h.OpenPorts())
	}
	return n
}

func (s Scan) ServiceTally() []ServiceCount {
	counts := map[string]int{}
	for _, h := range s.Hosts {
		for _, p := range h.OpenPorts() {
			name := "unknown"
			if p.Service != nil && p.Service.Name != "" {
				name = p.Service.Name
			}
			counts[name]++
		}
	}
	out := make([]ServiceCount, 0, len(counts))
	for name, n := range counts {
		out = append(out, ServiceCount{Name: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

type ServiceCount struct {
	Name  string
	Count int
}

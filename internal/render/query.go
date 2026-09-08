package render

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/3xh4u573d/wmap/internal/query"
)

func HostList(w io.Writer, matches []query.Match) {
	for _, ip := range query.Hosts(matches) {
		fmt.Fprintln(w, ip)
	}
}

func TargetList(w io.Writer, matches []query.Match) {
	for _, t := range query.Targets(matches) {
		fmt.Fprintln(w, t)
	}
}

func Matches(w io.Writer, matches []query.Match, color bool) {
	s := Styles{Color: color}
	if len(matches) == 0 {
		fmt.Fprintln(w, s.Dim("no matches"))
		return
	}

	multi := scanCount(matches) > 1
	headers := []string{"HOST", "NAME", "PORT", "STATE", "SERVICE", "VERSION"}
	if multi {
		headers = append([]string{"SCAN"}, headers...)
	}
	g := &grid{headers: headers}
	for _, m := range matches {
		var row []cell
		if multi {
			row = append(row, txt(scanName(m)))
		}
		var svc, ver string
		if m.Port.Service != nil {
			svc = m.Port.Service.Label()
			ver = m.Port.Service.Banner()
		}
		row = append(row,
			txt(m.Host.IP()),
			txt(m.Host.Name()),
			txt(fmt.Sprintf("%d/%s", m.Port.ID, m.Port.Protocol)),
			cell{text: m.Port.State, style: s.State},
			cell{text: svc, style: s.Service},
			txt(ver),
		)
		g.add(row...)
	}
	g.write(w, s)
	fmt.Fprintln(w, s.Dim(fmt.Sprintf("%s · %s",
		plural(len(matches), "match", "matches"),
		plural(len(query.Hosts(matches)), "host", "hosts"))))
}

func MatchesJSON(w io.Writer, matches []query.Match) error {
	type row struct {
		Scan      string   `json:"scan,omitempty"`
		IP        string   `json:"ip"`
		Hostname  string   `json:"hostname,omitempty"`
		Port      int      `json:"port"`
		Proto     string   `json:"proto"`
		State     string   `json:"state"`
		Service   string   `json:"service,omitempty"`
		Product   string   `json:"product,omitempty"`
		Version   string   `json:"version,omitempty"`
		ExtraInfo string   `json:"extrainfo,omitempty"`
		Tunnel    string   `json:"tunnel,omitempty"`
		OSType    string   `json:"ostype,omitempty"`
		CPEs      []string `json:"cpes,omitempty"`
	}
	out := make([]row, 0, len(matches))
	for _, m := range matches {
		r := row{
			Scan:     scanName(m),
			IP:       m.Host.IP(),
			Hostname: m.Host.Name(),
			Port:     m.Port.ID,
			Proto:    m.Port.Protocol,
			State:    m.Port.State,
		}
		if sv := m.Port.Service; sv != nil {
			r.Service = sv.Name
			r.Product = sv.Product
			r.Version = sv.Version
			r.ExtraInfo = sv.ExtraInfo
			r.Tunnel = sv.Tunnel
			r.OSType = sv.OSType
			r.CPEs = sv.CPEs
		}
		out = append(out, r)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func scanName(m query.Match) string {
	if m.Scan == nil || m.Scan.Source == "" {
		return ""
	}
	return filepath.Base(m.Scan.Source)
}

func scanCount(matches []query.Match) int {
	seen := map[string]bool{}
	for _, m := range matches {
		seen[scanName(m)] = true
	}
	return len(seen)
}

package render

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/3xh4u573d/wmap/internal/model"
)

type OverviewOptions struct {
	All     bool
	Flat    bool
	Verbose bool
	Color   bool
}

func Overview(w io.Writer, scans []model.Scan, opt OverviewOptions) {
	s := Styles{Color: opt.Color}
	for i := range scans {
		if i > 0 {
			fmt.Fprintf(w, "\n%s\n\n", s.Dim(strings.Repeat("-", 48)))
		}
		if opt.Flat {
			overviewFlat(w, s, scans[i], opt)
		} else {
			overviewGrouped(w, s, scans[i], opt)
		}
	}
}

func scanHeader(w io.Writer, s Styles, scan model.Scan) {
	name := "scan"
	if scan.Source != "" {
		name = filepath.Base(scan.Source)
	}
	line := s.Title(name)
	if a := cleanArgs(scan.Args); a != "" {
		line += "  " + s.Dim(a)
	}
	fmt.Fprintln(w, line)

	bits := []string{plural(len(scan.UpHosts()), "host up", "hosts up")}
	if d := len(scan.DownHosts()); d > 0 {
		bits = append(bits, fmt.Sprintf("%d down", d))
	}
	bits = append(bits, plural(scan.CountOpenPorts(), "open port", "open ports"))
	if !scan.Start.IsZero() {
		bits = append(bits, scan.Start.Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(w, s.Dim(strings.Join(bits, " · ")))
	if scan.Partial {
		fmt.Fprintln(w, s.Changed("! partial output — scan did not finish; results may be incomplete"))
	}
}

func cleanArgs(args string) string {
	args = strings.ReplaceAll(args, `\\`, `\`)
	low := strings.ToLower(args)
	for _, marker := range []string{"nmap.exe ", "nmap "} {
		if i := strings.Index(low, marker); i >= 0 {
			return strings.TrimSpace(args[i+len(marker):])
		}
	}
	return args
}

func overviewGrouped(w io.Writer, s Styles, scan model.Scan, opt OverviewOptions) {
	scanHeader(w, s, scan)
	hosts := scan.UpHosts()
	if len(hosts) == 0 {
		fmt.Fprintln(w, s.Dim("  (no hosts up)"))
		return
	}
	for _, h := range hosts {
		fmt.Fprintln(w)
		title := s.Title(h.Label())
		var tail []string
		if mac := h.Addresses["mac"]; mac != "" && mac != h.IP() {
			m := mac
			if h.Vendor != "" {
				m += " (" + h.Vendor + ")"
			}
			tail = append(tail, "MAC "+m)
		}
		if om, ok := h.BestOS(); ok {
			tail = append(tail, om.Name)
		}
		if len(tail) > 0 {
			title += "  " + s.Dim(strings.Join(tail, " · "))
		}
		fmt.Fprintln(w, title)

		g := &grid{headers: []string{"PORT", "STATE", "SERVICE", "VERSION"}, indent: "  "}
		for _, p := range h.SortedPorts() {
			if !opt.All && !p.IsOpen() {
				continue
			}
			var svc, ver string
			if p.Service != nil {
				svc = p.Service.Label()
				ver = p.Service.Banner()
			}
			g.add(
				txt(fmt.Sprintf("%d/%s", p.ID, p.Protocol)),
				cell{text: p.State, style: s.State},
				cell{text: svc, style: s.Service},
				txt(ver),
			)
		}
		if g.empty() {
			if len(h.Ports) == 0 {
				fmt.Fprintln(w, s.Dim("  (no ports scanned)"))
			} else {
				fmt.Fprintln(w, s.Dim("  (no open ports)"))
			}
		} else {
			g.write(w, s)
		}
		writeScripts(w, s, h, opt.Verbose)
	}
}

func overviewFlat(w io.Writer, s Styles, scan model.Scan, opt OverviewOptions) {
	scanHeader(w, s, scan)
	fmt.Fprintln(w)
	g := &grid{headers: []string{"HOST", "NAME", "PORT", "STATE", "SERVICE", "VERSION"}}
	for _, h := range scan.UpHosts() {
		for _, p := range h.SortedPorts() {
			if !opt.All && !p.IsOpen() {
				continue
			}
			var svc, ver string
			if p.Service != nil {
				svc = p.Service.Label()
				ver = p.Service.Banner()
			}
			g.add(
				txt(h.IP()),
				txt(h.Name()),
				txt(fmt.Sprintf("%d/%s", p.ID, p.Protocol)),
				cell{text: p.State, style: s.State},
				cell{text: svc, style: s.Service},
				txt(ver),
			)
		}
	}
	if g.empty() {
		fmt.Fprintln(w, s.Dim("(no matching ports)"))
		return
	}
	g.write(w, s)
}

func writeScripts(w io.Writer, s Styles, h model.Host, verbose bool) {
	type tagged struct {
		where string
		sc    model.Script
	}
	var all []tagged
	for _, p := range h.SortedPorts() {
		for _, sc := range p.Scripts {
			all = append(all, tagged{fmt.Sprintf("%d/%s", p.ID, p.Protocol), sc})
		}
	}
	for _, sc := range h.HostScripts {
		all = append(all, tagged{"host", sc})
	}
	if len(all) == 0 {
		return
	}
	if !verbose {
		ids := make([]string, 0, len(all))
		for _, t := range all {
			ids = append(ids, t.sc.ID)
		}
		fmt.Fprintln(w, s.Dim("  scripts: "+strings.Join(ids, ", ")+"  (-v to expand)"))
		return
	}
	for _, t := range all {
		fmt.Fprintf(w, "  %s %s\n", s.Dim(t.where), s.Head(t.sc.ID))
		for _, line := range scriptLines(t.sc.Output) {
			fmt.Fprintf(w, "    %s\n", line)
		}
	}
}

func scriptLines(out string) []string {
	raw := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	for len(raw) > 0 && strings.TrimSpace(raw[0]) == "" {
		raw = raw[1:]
	}
	for len(raw) > 0 && strings.TrimSpace(raw[len(raw)-1]) == "" {
		raw = raw[:len(raw)-1]
	}
	trim := -1
	for _, l := range raw {
		if strings.TrimSpace(l) == "" {
			continue
		}
		n := len(l) - len(strings.TrimLeft(l, " "))
		if trim < 0 || n < trim {
			trim = n
		}
	}
	if trim > 0 {
		for i, l := range raw {
			if len(l) >= trim {
				raw[i] = l[trim:]
			}
		}
	}
	return raw
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

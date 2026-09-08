package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/3xh4u573d/wmap/internal/diff"
	"github.com/3xh4u573d/wmap/internal/model"
)

func DiffText(w io.Writer, d diff.Diff, color bool) {
	s := Styles{Color: color}
	fmt.Fprintln(w, s.Dim(d.OldLabel+"  ->  "+d.NewLabel))
	if d.Empty() {
		fmt.Fprintln(w, s.Dim("no changes"))
		return
	}

	for _, h := range d.Added {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s %s\n", s.Added("+ host"), s.Title(h.Label()))
		for _, p := range h.OpenPorts() {
			fmt.Fprintf(w, "    %-9s %s\n", portID(p), serviceText(p))
		}
	}
	for _, h := range d.Removed {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s %s\n", s.Removed("- host"), s.Title(h.Label()))
		for _, p := range h.OpenPorts() {
			fmt.Fprintf(w, "    %-9s %s\n", portID(p), serviceText(p))
		}
	}
	for _, hd := range d.Changed {
		fmt.Fprintln(w)
		fmt.Fprintln(w, s.Title(hd.Label))
		for _, p := range hd.Opened {
			fmt.Fprintf(w, "    %s %-9s %s\n", s.Added("+ opened "), portID(p), serviceText(p))
		}
		for _, p := range hd.Closed {
			fmt.Fprintf(w, "    %s %-9s %s\n", s.Removed("- closed "), portID(p), serviceText(p))
		}
		for _, c := range hd.Services {
			fmt.Fprintf(w, "    %s %-9s %s  ->  %s\n",
				s.Changed("~ version"), fmt.Sprintf("%d/%s", c.Port, c.Proto),
				orNone(c.Before), orNone(c.After))
		}
	}
}

func DiffJSON(w io.Writer, d diff.Diff) error {
	type svc struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Before string `json:"before"`
		After  string `json:"after"`
	}
	type host struct {
		IP       string   `json:"ip"`
		Opened   []string `json:"opened,omitempty"`
		Closed   []string `json:"closed,omitempty"`
		Services []svc    `json:"services,omitempty"`
	}
	type doc struct {
		Old     string   `json:"old"`
		New     string   `json:"new"`
		Added   []string `json:"added_hosts,omitempty"`
		Removed []string `json:"removed_hosts,omitempty"`
		Changed []host   `json:"changed,omitempty"`
	}
	out := doc{Old: d.OldLabel, New: d.NewLabel}
	for _, h := range d.Added {
		out.Added = append(out.Added, h.IP())
	}
	for _, h := range d.Removed {
		out.Removed = append(out.Removed, h.IP())
	}
	for _, hd := range d.Changed {
		hc := host{IP: hd.IP}
		for _, p := range hd.Opened {
			hc.Opened = append(hc.Opened, portID(p))
		}
		for _, p := range hd.Closed {
			hc.Closed = append(hc.Closed, portID(p))
		}
		for _, c := range hd.Services {
			hc.Services = append(hc.Services, svc{Port: c.Port, Proto: c.Proto, Before: c.Before, After: c.After})
		}
		out.Changed = append(out.Changed, hc)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func portID(p model.Port) string { return fmt.Sprintf("%d/%s", p.ID, p.Protocol) }

func serviceText(p model.Port) string {
	if p.Service == nil {
		return ""
	}
	out := p.Service.Label()
	if b := p.Service.Banner(); b != "" {
		if out != "" {
			out += "  "
		}
		out += b
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

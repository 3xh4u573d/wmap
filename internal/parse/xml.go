package parse

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/3xh4u573d/wmap/internal/model"
)

type xmlScanInfo struct {
	Type     string `xml:"type,attr"`
	Protocol string `xml:"protocol,attr"`
}

type xmlRunStats struct {
	Finished xmlFinished `xml:"finished"`
}

type xmlFinished struct {
	Time    int64   `xml:"time,attr"`
	Elapsed float64 `xml:"elapsed,attr"`
	Exit    string  `xml:"exit,attr"`
	Summary string  `xml:"summary,attr"`
}

type xmlHost struct {
	StartTime   int64         `xml:"starttime,attr"`
	EndTime     int64         `xml:"endtime,attr"`
	Status      xmlStatus     `xml:"status"`
	Addresses   []xmlAddress  `xml:"address"`
	Hostnames   []xmlHostname `xml:"hostnames>hostname"`
	Ports       []xmlPort     `xml:"ports>port"`
	OSMatches   []xmlOSMatch  `xml:"os>osmatch"`
	HostScripts []xmlScript   `xml:"hostscript>script"`
	Distance    xmlDistance   `xml:"distance"`
}

type xmlDistance struct {
	Value int `xml:"value,attr"`
}

type xmlStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   string       `xml:"portid,attr"`
	State    xmlPortState `xml:"state"`
	Service  *xmlService  `xml:"service"`
	Scripts  []xmlScript  `xml:"script"`
}

type xmlPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type xmlService struct {
	Name       string   `xml:"name,attr"`
	Product    string   `xml:"product,attr"`
	Version    string   `xml:"version,attr"`
	ExtraInfo  string   `xml:"extrainfo,attr"`
	OSType     string   `xml:"ostype,attr"`
	DeviceType string   `xml:"devicetype,attr"`
	Hostname   string   `xml:"hostname,attr"`
	Method     string   `xml:"method,attr"`
	Conf       int      `xml:"conf,attr"`
	Tunnel     string   `xml:"tunnel,attr"`
	CPEs       []string `xml:"cpe"`
}

type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type xmlOSMatch struct {
	Name     string       `xml:"name,attr"`
	Accuracy int          `xml:"accuracy,attr"`
	Classes  []xmlOSClass `xml:"osclass"`
}

type xmlOSClass struct {
	Vendor   string   `xml:"vendor,attr"`
	OSFamily string   `xml:"osfamily,attr"`
	CPEs     []string `xml:"cpe"`
}

func XML(data []byte, source string) (model.Scan, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }

	scan := model.Scan{Source: source}
	var sawRun, sawStats bool

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if sawRun {
				scan.Partial = true
				return finalize(scan, sawStats), nil
			}
			return model.Scan{}, fmt.Errorf("parse nmap xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "nmaprun":
			sawRun = true
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "scanner":
					scan.Scanner = a.Value
				case "args":
					scan.Args = a.Value
				case "version":
					scan.Version = a.Value
				case "start":
					scan.Start = unixString(a.Value)
				}
			}
		case "scaninfo":
			var si xmlScanInfo
			if err := dec.DecodeElement(&si, &se); err == nil && si.Type != "" {
				scan.ScanTypes = appendUniq(scan.ScanTypes, si.Type)
			}
		case "host":
			var xh xmlHost
			if err := dec.DecodeElement(&xh, &se); err != nil {
				if sawRun {
					scan.Partial = true
					return finalize(scan, sawStats), nil
				}
				return model.Scan{}, fmt.Errorf("parse host: %w", err)
			}
			scan.Hosts = append(scan.Hosts, convertHost(xh))
		case "runstats":
			var rs xmlRunStats
			if err := dec.DecodeElement(&rs, &se); err == nil {
				sawStats = true
				scan.Elapsed = rs.Finished.Elapsed
				scan.ExitStatus = rs.Finished.Exit
				if rs.Finished.Time > 0 {
					scan.End = time.Unix(rs.Finished.Time, 0)
				}
			}
		}
	}

	if !sawRun {
		return model.Scan{}, fmt.Errorf("not an nmap xml file (no <nmaprun> element)")
	}
	return finalize(scan, sawStats), nil
}

func finalize(s model.Scan, sawStats bool) model.Scan {
	if s.Scanner == "" {
		s.Scanner = "nmap"
	}
	if !sawStats {
		s.Partial = true
	}
	return s
}

func convertHost(xh xmlHost) model.Host {
	h := model.Host{
		Up:          xh.Status.State == "up",
		StateReason: xh.Status.Reason,
		Addresses:   map[string]string{},
		Distance:    xh.Distance.Value,
	}
	if xh.StartTime > 0 {
		h.StartTime = time.Unix(xh.StartTime, 0)
	}
	if xh.EndTime > 0 {
		h.EndTime = time.Unix(xh.EndTime, 0)
	}

	for _, a := range xh.Addresses {
		if a.Addr == "" {
			continue
		}
		switch a.AddrType {
		case "ipv4", "ipv6", "mac":
			h.Addresses[a.AddrType] = a.Addr
		default:
			if h.Addresses["ipv4"] == "" {
				h.Addresses["ipv4"] = a.Addr
			}
		}
		if a.AddrType == "mac" && a.Vendor != "" {
			h.Vendor = a.Vendor
		}
	}
	for _, hn := range xh.Hostnames {
		if hn.Name != "" {
			h.Hostnames = appendUniq(h.Hostnames, hn.Name)
		}
	}

	for _, xp := range xh.Ports {
		id, err := strconv.Atoi(strings.TrimSpace(xp.PortID))
		if err != nil {
			continue
		}
		p := model.Port{
			Protocol: firstNonEmpty(xp.Protocol, "tcp"),
			ID:       id,
			State:    firstNonEmpty(xp.State.State, "unknown"),
			Reason:   xp.State.Reason,
		}
		if xp.Service != nil {
			p.Service = &model.Service{
				Name:       xp.Service.Name,
				Product:    xp.Service.Product,
				Version:    xp.Service.Version,
				ExtraInfo:  xp.Service.ExtraInfo,
				OSType:     xp.Service.OSType,
				DeviceType: xp.Service.DeviceType,
				Hostname:   xp.Service.Hostname,
				Method:     xp.Service.Method,
				Conf:       xp.Service.Conf,
				Tunnel:     xp.Service.Tunnel,
				CPEs:       dedupeStrings(xp.Service.CPEs),
			}
		}
		for _, s := range xp.Scripts {
			if s.ID != "" || s.Output != "" {
				p.Scripts = append(p.Scripts, model.Script{ID: s.ID, Output: s.Output})
			}
		}
		h.Ports = append(h.Ports, p)
	}

	for _, m := range xh.OSMatches {
		if m.Name == "" {
			continue
		}
		om := model.OSMatch{Name: m.Name, Accuracy: m.Accuracy}
		for _, c := range m.Classes {
			om.CPEs = append(om.CPEs, c.CPEs...)
		}
		om.CPEs = dedupeStrings(om.CPEs)
		h.OSMatches = append(h.OSMatches, om)
	}
	for _, s := range xh.HostScripts {
		if s.ID != "" || s.Output != "" {
			h.HostScripts = append(h.HostScripts, model.Script{ID: s.ID, Output: s.Output})
		}
	}
	return h
}

func unixString(s string) time.Time {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func dedupeStrings(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(xs))
	var out []string
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

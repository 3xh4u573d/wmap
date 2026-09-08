package parse

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"github.com/3xh4u573d/wmap/internal/model"
)

func Gnmap(data []byte, source string) (model.Scan, error) {
	scan := model.Scan{Scanner: "nmap", Source: source}
	byIP := map[string]*model.Host{}
	var order []string

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "# Nmap") {
			if i := strings.Index(line, " as: "); i >= 0 && scan.Args == "" {
				scan.Args = strings.TrimSpace(line[i+len(" as: "):])
			}
			continue
		}
		if !strings.HasPrefix(line, "Host: ") {
			continue
		}

		fields := strings.Split(line, "\t")
		ip, hostname := splitHostField(fields[0])
		if ip == "" {
			continue
		}
		h := byIP[ip]
		if h == nil {
			h = &model.Host{Addresses: map[string]string{"ipv4": ip}}
			byIP[ip] = h
			order = append(order, ip)
		}
		if hostname != "" {
			h.Hostnames = appendUniq(h.Hostnames, hostname)
		}

		for _, f := range fields[1:] {
			switch {
			case strings.HasPrefix(f, "Status: "):
				h.Up = strings.TrimPrefix(f, "Status: ") == "Up"
			case strings.HasPrefix(f, "Ports: "):
				h.Up = true
				parseGnmapPorts(h, strings.TrimPrefix(f, "Ports: "))
			case strings.HasPrefix(f, "OS: "):
				if name := strings.TrimPrefix(f, "OS: "); name != "" {
					h.OSMatches = append(h.OSMatches, model.OSMatch{Name: name})
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return model.Scan{}, err
	}
	for _, ip := range order {
		scan.Hosts = append(scan.Hosts, *byIP[ip])
	}
	return scan, nil
}

func splitHostField(f string) (ip, hostname string) {
	rest := strings.TrimSpace(strings.TrimPrefix(f, "Host: "))
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		ip = rest[:sp]
		paren := strings.TrimSpace(rest[sp:])
		hostname = strings.TrimSuffix(strings.TrimPrefix(paren, "("), ")")
	} else {
		ip = rest
	}
	return ip, hostname
}

func parseGnmapPorts(h *model.Host, s string) {
	for _, chunk := range strings.Split(s, ", ") {
		parts := strings.Split(chunk, "/")
		if len(parts) < 3 {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}
		p := model.Port{
			ID:       id,
			State:    strings.TrimSpace(parts[1]),
			Protocol: strings.TrimSpace(parts[2]),
		}
		var name, version string
		if len(parts) > 4 {
			name = strings.TrimSpace(parts[4])
		}
		if len(parts) > 6 {
			version = strings.TrimSpace(parts[6])
		}
		if name != "" || version != "" {

			p.Service = &model.Service{Name: name, Product: version, Method: "table"}
		}
		h.Ports = append(h.Ports, p)
	}
}

func appendUniq(xs []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return xs
	}
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

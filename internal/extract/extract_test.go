package extract

import (
	"reflect"
	"testing"

	"github.com/3xh4u573d/wmap/internal/model"
)

func svc(name, tunnel string) *model.Service { return &model.Service{Name: name, Tunnel: tunnel} }

func host(ip, name string, ports ...model.Port) model.Host {
	h := model.Host{Up: true, Addresses: map[string]string{}, Ports: ports}
	if ip != "" {
		if len(ip) > 0 && ip[0] >= '0' && ip[0] <= '9' && !hasColon(ip) {
			h.Addresses["ipv4"] = ip
		} else {
			h.Addresses["ipv6"] = ip
		}
	}
	if name != "" {
		h.Hostnames = []string{name}
	}
	return h
}
func hasColon(s string) bool {
	for _, r := range s {
		if r == ':' {
			return true
		}
	}
	return false
}

func p(id int, state, proto string, s *model.Service) model.Port {
	return model.Port{ID: id, State: state, Protocol: proto, Service: s}
}

func scan(hosts ...model.Host) []model.Scan { return []model.Scan{{Hosts: hosts}} }

func run(t *testing.T, scans []model.Scan, opt Options) []string {
	t.Helper()
	return Run(scans, opt)
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("\n got: %v\nwant: %v", got, want)
	}
}

var web = host("10.0.0.5", "web.lan",
	p(22, "open", "tcp", svc("ssh", "")),
	p(80, "open", "tcp", svc("http", "")),
	p(443, "open", "tcp", svc("http", "ssl")),
	p(8080, "open", "tcp", svc("http-proxy", "")),
	p(8443, "open", "tcp", svc("https-alt", "")),
	p(9200, "open", "tcp", nil),
	p(3306, "open", "tcp", svc("mysql", "")),
	p(9999, "filtered", "tcp", svc("http", "")),
)

func TestHosts(t *testing.T) {
	eq(t, run(t, scan(web), Options{Mode: ModeHosts}), []string{"10.0.0.5"})
	eq(t, run(t, scan(web), Options{Mode: ModeHosts, Ports: []int{3306}}), []string{"10.0.0.5"})
	eq(t, run(t, scan(web), Options{Mode: ModeHosts, Ports: []int{7777}}), nil)
	eq(t, run(t, scan(web), Options{Mode: ModeHosts, Ports: []int{9999}, Filtered: true}), []string{"10.0.0.5"})
	eq(t, run(t, scan(web), Options{Mode: ModeHosts, Ports: []int{9999}}), nil)
	eq(t, run(t, scan(web), Options{Mode: ModeHosts, Names: true}), []string{"web.lan"})
}

func TestURLs(t *testing.T) {
	got := run(t, scan(web), Options{Mode: ModeURLs})
	eq(t, got, []string{
		"ssh://10.0.0.5",
		"http://10.0.0.5",
		"https://10.0.0.5",
		"mysql://10.0.0.5",
		"http://10.0.0.5:8080",
		"https://10.0.0.5:8443",
	})
}

func TestHTTPURLs(t *testing.T) {
	got := run(t, scan(web), Options{Mode: ModeHTTPURLs})
	eq(t, got, []string{
		"http://10.0.0.5",
		"https://10.0.0.5",
		"http://10.0.0.5:8080",
		"https://10.0.0.5:8443",
		"http://10.0.0.5:9200",
	})
}

func TestURLsAll(t *testing.T) {
	h := host("10.0.0.9", "", p(333, "open", "tcp", nil), p(6100, "open", "tcp", nil))
	got := run(t, scan(h), Options{Mode: ModeURLsAll})
	eq(t, got, []string{
		"http://10.0.0.9:333",
		"http://10.0.0.9:6100",
		"https://10.0.0.9:333",
		"https://10.0.0.9:6100",
	})
}

func TestIPv6Bracketing(t *testing.T) {
	h := host("2001:db8::1", "", p(8443, "open", "tcp", svc("ssl/http", "ssl")))
	eq(t, run(t, scan(h), Options{Mode: ModeHTTPURLs}), []string{"https://[2001:db8::1]:8443"})
	eq(t, run(t, scan(h), Options{Mode: ModeURLsAll}), []string{
		"http://[2001:db8::1]:8443", "https://[2001:db8::1]:8443",
	})
}

func TestDedupAcrossScans(t *testing.T) {
	a := scan(host("10.0.0.5", "", p(80, "open", "tcp", svc("http", ""))))
	b := scan(host("10.0.0.5", "", p(80, "open", "tcp", svc("http", ""))))
	got := Run([]model.Scan{a[0], b[0]}, Options{Mode: ModeURLs})
	eq(t, got, []string{"http://10.0.0.5"})
}

func TestDownHostSkipped(t *testing.T) {
	down := model.Host{Up: false, Addresses: map[string]string{"ipv4": "10.0.0.9"},
		Ports: []model.Port{p(80, "open", "tcp", svc("http", ""))}}
	eq(t, run(t, scan(down), Options{Mode: ModeHosts}), nil)
}

func TestFilteredMode(t *testing.T) {
	eq(t, run(t, scan(web), Options{Mode: ModeHTTPURLs, Filtered: true}),
		[]string{"http://10.0.0.5:9999"})

	got := run(t, scan(web), Options{Mode: ModeHosts, Open: true, Filtered: true})
	eq(t, got, []string{"10.0.0.5"})
}

func TestWebURLPortFallbackRespectsProbe(t *testing.T) {
	probed := &model.Service{Name: "ppp", Method: "probed"}
	guessed := &model.Service{Name: "ppp", Method: "table"}
	h1 := host("10.0.0.1", "", model.Port{ID: 3000, State: "open", Protocol: "tcp", Service: probed})
	h2 := host("10.0.0.2", "", model.Port{ID: 3000, State: "open", Protocol: "tcp", Service: guessed})
	eq(t, run(t, scan(h1), Options{Mode: ModeHTTPURLs}), nil)
	eq(t, run(t, scan(h2), Options{Mode: ModeHTTPURLs}), []string{"http://10.0.0.2:3000"})
}

func TestVerbose(t *testing.T) {
	h := host("10.0.0.5", "web.lan", p(80, "open", "tcp", &model.Service{Name: "http", Product: "nginx", Version: "1.18.0", Method: "probed"}))
	got := run(t, scan(h), Options{Mode: ModeURLs, Verbose: true})
	eq(t, got, []string{"http://10.0.0.5\t# 80/tcp http nginx 1.18.0"})

	plain := run(t, scan(h), Options{Mode: ModeURLs})
	eq(t, plain, []string{"http://10.0.0.5"})
}

func TestDiffHosts(t *testing.T) {
	old := model.Scan{Hosts: []model.Host{
		host("10.0.0.1", "", p(80, "open", "tcp", svc("http", ""))),
		host("10.0.0.2", "", p(22, "open", "tcp", svc("ssh", ""))),
	}}
	nw := model.Scan{Hosts: []model.Host{
		host("10.0.0.1", "", p(80, "open", "tcp", svc("http", ""))),
		host("10.0.0.3", "", p(443, "open", "tcp", svc("https", ""))),
	}}
	got := Run([]model.Scan{old, nw}, Options{Mode: ModeHosts, Diff: true})
	eq(t, got, []string{"+10.0.0.3", "-10.0.0.2"})
}

func TestDiffURLs(t *testing.T) {
	old := model.Scan{Hosts: []model.Host{host("10.0.0.1", "", p(80, "open", "tcp", svc("http", "")))}}
	nw := model.Scan{Hosts: []model.Host{host("10.0.0.1", "",
		p(80, "open", "tcp", svc("http", "")),
		p(443, "open", "tcp", svc("http", "ssl")))}}
	got := Run([]model.Scan{old, nw}, Options{Mode: ModeURLs, Diff: true})
	eq(t, got, []string{"+https://10.0.0.1"})
}

func TestDiffChanges(t *testing.T) {
	old := model.Scan{Hosts: []model.Host{host("10.0.0.1", "",
		p(22, "open", "tcp", &model.Service{Name: "ssh", Product: "OpenSSH", Version: "8.9"}),
		p(3306, "open", "tcp", svc("mysql", "")))}}
	nw := model.Scan{Hosts: []model.Host{host("10.0.0.1", "",
		p(22, "open", "tcp", &model.Service{Name: "ssh", Product: "OpenSSH", Version: "9.6"}),
		p(443, "open", "tcp", svc("https", "")))}}

	eq(t, Run([]model.Scan{old, nw}, Options{Mode: ModeChanges, Diff: true}), []string{
		"+10.0.0.1:443",
		"-10.0.0.1:3306",
		"~10.0.0.1:22\t# OpenSSH 8.9 -> OpenSSH 9.6",
	})

	eq(t, Run([]model.Scan{old, nw}, Options{Mode: ModeChanges, Diff: true, Verbose: true}), []string{
		"+10.0.0.1:443\t# 443/tcp https",
		"-10.0.0.1:3306\t# 3306/tcp mysql",
		"~10.0.0.1:22\t# OpenSSH 8.9 -> OpenSSH 9.6",
	})
}

package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const miniHost = `<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV x" start="1700000000" version="7.94">
<scaninfo type="syn" protocol="tcp"/>
<scaninfo type="udp" protocol="udp"/>
<host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="a.example" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.25 &amp; up" extrainfo="&lt;dev&gt;"><cpe>cpe:/a:x</cpe><cpe>cpe:/a:x</cpe></service>
<script id="http-title" output="line1&#10;line2"/>
</port>
<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/></port>
</ports>
<os><osmatch name="Linux 3.x" accuracy="90"/><osmatch name="Linux 5.x" accuracy="98"/></os>
</host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.2" addrtype="ipv4"/><hostnames/></host>
<runstats><finished time="1700000100" elapsed="100" exit="success"/></runstats>
</nmaprun>`

func TestXMLEntitiesAndShape(t *testing.T) {
	s, err := XML([]byte(miniHost), "mini.xml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Partial {
		t.Error("complete scan flagged partial")
	}
	if len(s.ScanTypes) != 2 {
		t.Errorf("scan types = %v", s.ScanTypes)
	}
	if len(s.UpHosts()) != 1 || len(s.DownHosts()) != 1 {
		t.Fatalf("up=%d down=%d", len(s.UpHosts()), len(s.DownHosts()))
	}
	h := s.UpHosts()[0]
	if h.Addresses["mac"] != "AA:BB:CC:00:11:22" || h.Vendor != "Acme" {
		t.Errorf("mac/vendor = %q / %q", h.Addresses["mac"], h.Vendor)
	}
	p80, _ := portByID(h.Ports, 80)
	if got := p80.Service.Version; got != "1.25 & up" {
		t.Errorf("version entity not decoded: %q", got)
	}
	if got := p80.Service.ExtraInfo; got != "<dev>" {
		t.Errorf("extrainfo entity not decoded: %q", got)
	}
	if len(p80.Service.CPEs) != 1 {
		t.Errorf("CPEs not deduped: %v", p80.Service.CPEs)
	}
	if !strings.Contains(p80.Scripts[0].Output, "\n") {
		t.Errorf("script newline entity not decoded: %q", p80.Scripts[0].Output)
	}
	p53, _ := portByID(h.Ports, 53)
	if !p53.IsOpen() {
		t.Error("open|filtered should count as open")
	}
	if om, _ := h.BestOS(); om.Name != "Linux 5.x" {
		t.Errorf("BestOS = %q, want highest-accuracy Linux 5.x", om.Name)
	}
}

func TestXMLTruncatedMidHost(t *testing.T) {
	cut := miniHost[:strings.Index(miniHost, "line2")]
	s, err := XML([]byte(cut), "cut.xml")
	if err != nil {
		t.Fatalf("truncated file should not hard-error: %v", err)
	}
	if !s.Partial {
		t.Error("truncated scan not flagged partial")
	}
}

func TestXMLNoRunstatsIsPartial(t *testing.T) {
	noStats := miniHost[:strings.Index(miniHost, "<runstats>")] + "</nmaprun>"
	s, err := XML([]byte(noStats), "x.xml")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Partial {
		t.Error("scan without <runstats> should be partial")
	}
	if len(s.Hosts) != 2 {
		t.Errorf("hosts = %d, want 2", len(s.Hosts))
	}
}

func TestXMLGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "not xml at all", "<html><body/></html>", "<rss><channel/></rss>"} {
		if _, err := XML([]byte(in), "g"); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestCorpusFilesParse(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "*.xml"))
	matches2, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "*.gnmap"))
	files := append(matches, matches2...)
	if len(files) == 0 {
		t.Skip("no testdata files")
	}
	for _, f := range files {
		f := f
		t.Run(filepath.Base(f), func(t *testing.T) {
			if _, err := os.Stat(f); err != nil {
				t.Skip()
			}
			s, err := File(f)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			for _, h := range s.Hosts {
				for _, p := range h.Ports {
					_ = p.Service.Banner()
				}
			}
		})
	}
}

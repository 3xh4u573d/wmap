# wmap

Post-process nmap output.

- a raw extractor for shell pipelines — pull host lists and URLs out of a scan
- readable terminal views — `view`, `query`, `diff`

Reads nmap XML (`-oX`) and grepable (`-oG`). Single static binary, builds for
macOS and Linux.

## Install

```
go install github.com/3xh4u573d/wmap@latest
```

The repository is private, so Go needs to fetch it directly rather than through
the module proxy:

```
export GOPRIVATE=github.com/3xh4u573d/*
go install github.com/3xh4u573d/wmap@latest
```

git must be able to authenticate to github.com (SSH key or a credential helper).

From a checkout:

```
git clone git@github.com:3xh4u573d/wmap.git
cd wmap && go build -o wmap .
```

Requires Go 1.23 or newer.

## Extractor

The root command. Output is always raw: one item per line, no colour, `\n`
endings, nothing on stderr unless it fails.

```
wmap -i scan.xml -h                    hosts with at least one open port
wmap -i scan.xml -h 445                hosts with 445 open
wmap -i scan.xml -h 80,443,8000-8100   hosts with any of those open
wmap -i scan.xml -u                    a URL per service (http, https, smb, ssh, mysql, ...)
wmap -i scan.xml -hu                   http and https URLs only, on any port
wmap -i scan.xml -uA                   http+https for every open TCP port
wmap -i old.xml -i new.xml -d          what changed between two scans
wmap -i scan.xml -u -v                 annotate each line
wmap -i a.xml -i b.xml -u -o urls.txt  write to a file
```

### Flags

```
-i, --input FILE    nmap -oX or -oG file; repeatable
-o, --output FILE   write here instead of stdout
-h, --hosts         output matching hosts
-u, --urls          output a URL per matching port, scheme from the service
    --http-urls     output http/https URLs only         (= -h -u, i.e. -hu)
-A, --all-ports     with -u, emit http+https per port    (= -u -A, i.e. -uA)
    --urls-all      = -u -A
-d, --diff          diff two -i inputs, old then new
    --open          open ports only (default)
    --filtered      filtered ports only
-n, --names         use the resolved hostname instead of the IP
-v, --verbose       append "\t# <detail>" to each line
[PORT...]           port filter: 445, 80,443, 8000-8100
```

`-h` means `--hosts` here. Use `--help` for help.

### Diff

`-d` takes exactly two `-i` files, old then new. On its own it lists
port-level changes:

```
$ wmap -i mon.xml -i tue.xml -d
+10.0.0.20:445
-10.0.0.15:21
~10.0.0.5:22   # OpenSSH 8.9p1 -> OpenSSH 9.6p1
```

`-d -h` gives host-level, `-d -u` and `-d -hu` give URL-level. Exit status is
1 when anything differs, 0 when the two scans match.

### Verbose

`-v` appends a tab and a `#` comment to every line, so the raw value survives
`cut -f1`:

```
$ wmap -i scan.xml -u -v
ssh://10.0.0.5          # 22/tcp ssh OpenSSH 9.6p1
https://10.0.0.5:8443   # 8443/tcp ssl/http nginx 1.25.3

$ wmap -i scan.xml -u -v | cut -f1
ssh://10.0.0.5
https://10.0.0.5:8443
```

### Notes

- `-u` emits URLs with a real scheme only; a port whose service nmap could not
  name is skipped. `-uA` is the exhaustive mode.
- URL modes look at TCP ports only. `-h` counts any protocol.
- `-hu` also treats well-known web ports (8080, 8443, ...) as http/https, but
  only when nmap's service detection was weak — a probed `kerberos-sec` on 88
  is never called http.
- `open|filtered` counts for both `--open` and `--filtered`.
- IPv6 hosts are bracketed: `https://[2001:db8::1]:8443`. Default ports are
  dropped: `http://host`, not `http://host:80`.

## Views

```
nmap -sV -sC -oX scan.xml 10.0.0.0/24

wmap view scan.xml            host / port / service tables
wmap view scan.xml -a -v      include closed and filtered, expand NSE output
wmap view scan.xml --flat     one row per host:port

wmap query scan.xml --port 445
wmap query scan.xml --web --hosts
wmap query scan.xml --product nginx --version 1.18
wmap query scan.xml --vuln

wmap diff old.xml new.xml     coloured change report, exit 1 on any change
```

`query` filters by host, port, state, service, product, version, CPE, NSE
script or OS, with `--web / --smb / --rdp / --ssh / --db / --vuln` shortcuts
and `--hosts / --targets / --json / --count` output modes.

## Parsing

XML is parsed as a stream, so a scan aborted mid-run still yields the hosts
nmap finished; those results are flagged partial. Grepable input works but
carries no script output, no CPEs and only a coarse version string — prefer
XML.

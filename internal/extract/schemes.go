package extract

import "strings"

func schemeForService(name, tunnel string) (scheme string, defPort int) {
	ssl := tunnel == "ssl" || tunnel == "tls" || strings.Contains(name, "ssl") || strings.Contains(name, "tls")

	switch {
	case strings.Contains(name, "https"):
		return "https", 443
	case strings.HasPrefix(name, "http"), name == "www", name == "http-alt",
		name == "http-proxy", name == "http-mgmt", name == "webcache", name == "caldav":
		if ssl {
			return "https", 443
		}
		return "http", 80
	}

	type sd struct {
		scheme string
		port   int
	}
	m := map[string]sd{
		"ssh":           {"ssh", 22},
		"telnet":        {"telnet", 23},
		"ftp":           {"ftp", 21},
		"ftps":          {"ftps", 990},
		"ftps-data":     {"ftps", 989},
		"smtp":          {"smtp", 25},
		"smtps":         {"smtps", 465},
		"submission":    {"smtp", 587},
		"imap":          {"imap", 143},
		"imaps":         {"imaps", 993},
		"pop3":          {"pop3", 110},
		"pop3s":         {"pop3s", 995},
		"ldap":          {"ldap", 389},
		"ldapssl":       {"ldaps", 636},
		"ldaps":         {"ldaps", 636},
		"globalcatldap": {"ldap", 3268},
		"microsoft-ds":  {"smb", 445},
		"netbios-ssn":   {"smb", 139},
		"smb":           {"smb", 445},
		"ms-wbt-server": {"rdp", 3389},
		"rdp":           {"rdp", 3389},
		"mysql":         {"mysql", 3306},
		"ms-sql-s":      {"mssql", 1433},
		"mssql":         {"mssql", 1433},
		"postgresql":    {"postgresql", 5432},
		"postgres":      {"postgresql", 5432},
		"mongodb":       {"mongodb", 27017},
		"mongod":        {"mongodb", 27017},
		"redis":         {"redis", 6379},
		"rsync":         {"rsync", 873},
		"nfs":           {"nfs", 2049},
		"sip":           {"sip", 5060},
		"sip-tls":       {"sips", 5061},
		"xmpp":          {"xmpp", 5222},
		"xmpp-client":   {"xmpp", 5222},
		"xmpp-server":   {"xmpp", 5269},
		"jabber":        {"xmpp", 5222},
		"irc":           {"irc", 6667},
		"ircs":          {"ircs", 6697},
		"ircs-u":        {"ircs", 6697},
		"ipp":           {"ipp", 631},
		"rtsp":          {"rtsp", 554},
		"vnc":           {"vnc", 5900},
		"svn":           {"svn", 3690},
		"svnserve":      {"svn", 3690},
		"git":           {"git", 9418},
		"amqp":          {"amqp", 5672},
		"mqtt":          {"mqtt", 1883},
		"nntp":          {"nntp", 119},
		"nntps":         {"nntps", 563},
		"gopher":        {"gopher", 70},
		"finger":        {"finger", 79},
		"ldap-admin":    {"ldap", 389},
	}
	if v, ok := m[name]; ok {
		return v.scheme, v.port
	}
	if strings.HasPrefix(name, "vnc") {
		return "vnc", 5900
	}
	return "", 0
}

var httpsPorts = map[int]bool{
	443: true, 832: true, 981: true, 1311: true, 2083: true, 2087: true, 2096: true,
	4443: true, 4712: true, 5443: true, 7443: true, 8443: true, 8834: true, 8843: true,
	9443: true, 10443: true, 12443: true, 18091: true, 18092: true,
}

var httpPorts = map[int]bool{
	80: true, 81: true, 300: true, 591: true, 593: true, 2080: true, 2480: true,
	3000: true, 3001: true, 3128: true, 3333: true, 4000: true, 4200: true, 4243: true,
	4567: true, 4711: true, 4993: true, 5000: true, 5001: true, 5104: true, 5108: true,
	5173: true, 5601: true, 5800: true, 6543: true, 7000: true, 7001: true, 7396: true,
	7474: true, 8000: true, 8001: true, 8008: true, 8014: true, 8042: true, 8060: true,
	8069: true, 8080: true, 8081: true, 8082: true, 8083: true, 8085: true, 8088: true,
	8090: true, 8091: true, 8100: true, 8118: true, 8123: true, 8161: true, 8172: true,
	8222: true, 8280: true, 8281: true, 8333: true, 8500: true, 8880: true, 8888: true,
	8983: true, 9000: true, 9001: true, 9002: true, 9043: true, 9060: true, 9080: true,
	9090: true, 9091: true, 9200: true, 9800: true, 9981: true, 15672: true, 16080: true,
	28017: true,
}

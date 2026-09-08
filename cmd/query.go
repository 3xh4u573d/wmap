package cmd

import (
	"fmt"

	"github.com/3xh4u573d/wmap/internal/query"
	"github.com/3xh4u573d/wmap/internal/render"
	"github.com/spf13/cobra"
)

func newQueryCmd() *cobra.Command {
	var (
		f         query.Filter
		sc        query.Shortcuts
		asHosts   bool
		asTargets bool
		asJSON    bool
		asCount   bool
	)
	c := &cobra.Command{
		Use:   "query <scan> [scan...]",
		Short: "Filter scan results by port, service, version, script or OS",
		Long: "Every condition is ANDed; repeating a flag ORs its values.\n" +
			"Default output is a table; --hosts / --targets / --json / --count\n" +
			"switch to machine-readable forms.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.ApplyShortcuts(sc)
			if err := f.Compile(); err != nil {
				return err
			}
			scans, err := loadScans(args)
			if err != nil {
				return err
			}
			matches := query.Run(scans, f)
			out := cmd.OutOrStdout()
			switch {
			case asCount:
				fmt.Fprintln(out, len(matches))
			case asHosts:
				render.HostList(out, matches)
			case asTargets:
				render.TargetList(out, matches)
			case asJSON:
				return render.MatchesJSON(out, matches)
			default:
				render.Matches(out, matches, useColor())
			}
			return nil
		},
	}

	fl := c.Flags()
	fl.StringSliceVar(&f.HostSpecs, "host", nil, "IP, CIDR or hostname substring")
	fl.StringSliceVarP(&f.PortSpecs, "port", "p", nil, "port 445, range 80-90, or list 22,80,443")
	fl.StringSliceVar(&f.States, "state", nil, "port state open|closed|filtered (default open)")
	fl.StringSliceVarP(&f.Services, "service", "s", nil, "service-name substring")
	fl.StringSliceVar(&f.Products, "product", nil, "service-product substring")
	fl.StringSliceVar(&f.Versions, "version", nil, "service-version substring")
	fl.StringSliceVar(&f.CPEs, "cpe", nil, "CPE substring")
	fl.StringSliceVar(&f.Scripts, "script", nil, "match an NSE script id or its output")
	fl.StringSliceVar(&f.OS, "os", nil, "OS-match substring")

	fl.BoolVar(&sc.Web, "web", false, "shortcut: HTTP(S) services")
	fl.BoolVar(&sc.SMB, "smb", false, "shortcut: SMB / NetBIOS")
	fl.BoolVar(&sc.RDP, "rdp", false, "shortcut: RDP")
	fl.BoolVar(&sc.SSH, "ssh", false, "shortcut: SSH")
	fl.BoolVar(&sc.DB, "db", false, "shortcut: common database services")
	fl.BoolVar(&sc.Vuln, "vuln", false, "shortcut: vuln* script or VULNERABLE output")

	fl.BoolVar(&asHosts, "hosts", false, "output matching host IPs, one per line")
	fl.BoolVar(&asTargets, "targets", false, "output ip:port, one per line")
	fl.BoolVar(&asJSON, "json", false, "output JSON")
	fl.BoolVar(&asCount, "count", false, "output the match count only")
	c.MarkFlagsMutuallyExclusive("hosts", "targets", "json", "count")
	return c
}

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/3xh4u573d/wmap/internal/extract"
	"github.com/3xh4u573d/wmap/internal/parse"
	"github.com/spf13/cobra"
)

var flagNoColor bool

func Execute() error { return newRoot().Execute() }

type extractFlags struct {
	inputs   []string
	output   string
	hosts    bool
	urls     bool
	allPorts bool
	httpURLs bool
	urlsAll  bool
	diff     bool
	open     bool
	filtered bool
	names    bool
	verbose  bool
}

func newRoot() *cobra.Command {
	var ef extractFlags

	root := &cobra.Command{
		Use:   "wmap [flags] [PORT...]",
		Short: "Extract hosts and URLs from nmap output (raw, pipe-friendly)",
		Long: `wmap reads nmap output and prints raw lists for piping.

  wmap -i scan.xml -h                 hosts that have an open port
  wmap -i scan.xml -h 445             hosts with 445 open
  wmap -i scan.xml -h 80,443,8000-8100  hosts with any of those open
  wmap -i scan.xml -u                 one URL per service (http, smb, ssh, ...)
  wmap -i scan.xml -hu                http(s) URLs only, any port (8443, ...)
  wmap -i scan.xml -uA                http+https for every open port
  wmap -i scan.xml -hu --filtered     http(s) URLs on filtered ports
  wmap -i old.xml -i new.xml -d       what changed (+/- ports, ~ versions)
  wmap -i old.xml -i new.xml -d -h    hosts that appeared / vanished
  wmap -i scan.xml -u -v              URLs, each annotated (cut -f1 to undo)
  wmap -i a.xml -i b.xml -u -o urls.txt

Everything prints raw, one per line, no colour. Subcommands view / query /
diff give the rich views.`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          func(cmd *cobra.Command, args []string) error { return runExtract(cmd, args, &ef) },
	}

	f := root.Flags()

	f.Bool("help", false, "help for wmap")
	f.StringSliceVarP(&ef.inputs, "input", "i", nil, "nmap XML (-oX) or grepable (-oG) file; repeatable")
	f.StringVarP(&ef.output, "output", "o", "", "write to this file instead of stdout")
	f.BoolVarP(&ef.hosts, "hosts", "h", false, "output: matching host addresses, one per line")
	f.BoolVarP(&ef.urls, "urls", "u", false, "output: one URL per matching port (scheme from service)")
	f.BoolVarP(&ef.allPorts, "all-ports", "A", false, "with -u: http+https URL for every matching port")
	f.BoolVar(&ef.httpURLs, "http-urls", false, "output: only http:// and https:// URLs  (same as -h -u)")
	f.BoolVar(&ef.urlsAll, "urls-all", false, "output: http+https for every matching port  (same as -u -A)")
	f.BoolVarP(&ef.diff, "diff", "d", false, "diff two -i inputs (old then new): +/- ports, ~ version changes")
	f.BoolVar(&ef.open, "open", false, "only open ports  (this is the default)")
	f.BoolVar(&ef.filtered, "filtered", false, "only filtered ports")
	f.BoolVarP(&ef.names, "names", "n", false, "use the resolved hostname instead of the IP")
	f.BoolVarP(&ef.verbose, "verbose", "v", false, "annotate each line with '\\t# <detail>' (cut -f1 to strip)")

	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colour (view / query / diff)")
	root.AddCommand(newViewCmd(), newQueryCmd(), newDiffCmd(), newVersionCmd())
	return root
}

func useColor() bool { return !flagNoColor }

func runExtract(cmd *cobra.Command, args []string, ef *extractFlags) error {
	if cmd.Flags().NFlag() == 0 && len(args) == 0 {
		return cmd.Help()
	}
	if len(ef.inputs) == 0 {
		return errors.New("no input: pass -i/--input <nmap xml or gnmap file>")
	}
	if ef.diff && len(ef.inputs) != 2 {
		return fmt.Errorf("diff needs exactly two -i inputs (old then new); got %d", len(ef.inputs))
	}

	ports, err := parsePortArgs(args)
	if err != nil {
		return err
	}
	mode, err := resolveMode(ef)
	if err != nil {
		return err
	}
	scans, err := parse.Files(ef.inputs)
	if err != nil {
		return err
	}

	lines := extract.Run(scans, extract.Options{
		Mode:     mode,
		Ports:    ports,
		Open:     ef.open,
		Filtered: ef.filtered,
		Names:    ef.names,
		Verbose:  ef.verbose,
		Diff:     ef.diff,
	})
	if err := writeLines(ef.output, lines); err != nil {
		return err
	}
	if ef.diff && len(lines) > 0 {
		return exitErr{code: 1}
	}
	return nil
}

func resolveMode(ef *extractFlags) (extract.Mode, error) {
	switch {
	case ef.urlsAll || (ef.urls && ef.allPorts):
		return extract.ModeURLsAll, nil
	case ef.httpURLs || (ef.hosts && ef.urls):
		return extract.ModeHTTPURLs, nil
	case ef.urls:
		return extract.ModeURLs, nil
	case ef.hosts:
		return extract.ModeHosts, nil
	case ef.diff:
		return extract.ModeChanges, nil
	default:
		return 0, errors.New("choose an output: -h (hosts), -u (urls), -hu (http urls), -uA (all ports) or -d (diff)")
	}
}

func parsePortArgs(args []string) ([]int, error) {
	var ports []int
	for _, a := range args {
		for _, part := range strings.Split(a, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if lo, hi, isRange := strings.Cut(part, "-"); isRange {
				a1, e1 := strconv.Atoi(strings.TrimSpace(lo))
				b1, e2 := strconv.Atoi(strings.TrimSpace(hi))
				if e1 != nil || e2 != nil || a1 < 0 || b1 > 65535 || a1 > b1 {
					return nil, fmt.Errorf("bad port range %q", part)
				}
				for p := a1; p <= b1; p++ {
					ports = append(ports, p)
				}
				continue
			}
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n > 65535 {
				return nil, fmt.Errorf("bad port %q (expected a number, list or range)", part)
			}
			ports = append(ports, n)
		}
	}
	return ports, nil
}

func writeLines(path string, lines []string) error {
	out := os.Stdout
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	w := bufio.NewWriter(out)
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return w.Flush()
}

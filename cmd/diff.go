package cmd

import (
	"github.com/3xh4u573d/wmap/internal/diff"
	"github.com/3xh4u573d/wmap/internal/render"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var asJSON, exitZero bool
	c := &cobra.Command{
		Use:   "diff <old> <new>",
		Short: "Show what changed between two scans",
		Long: "Reports hosts that appeared or vanished, ports that opened or\n" +
			"closed, and services whose version moved. Exits 1 when anything\n" +
			"changed, unless --exit-zero is given.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			scans, err := loadScans(args)
			if err != nil {
				return err
			}
			d := diff.Compute(scans[0], scans[1])
			if asJSON {
				if err := render.DiffJSON(cmd.OutOrStdout(), d); err != nil {
					return err
				}
			} else {
				render.DiffText(cmd.OutOrStdout(), d, useColor())
			}
			if !d.Empty() && !exitZero {
				return exitErr{code: 1}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	c.Flags().BoolVar(&exitZero, "exit-zero", false, "exit 0 even when there are changes")
	return c
}

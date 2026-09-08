package cmd

import (
	"github.com/3xh4u573d/wmap/internal/render"
	"github.com/spf13/cobra"
)

func newViewCmd() *cobra.Command {
	var all, flat, verbose bool
	c := &cobra.Command{
		Use:   "view <scan> [scan...]",
		Short: "Readable overview of one or more scans",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scans, err := loadScans(args)
			if err != nil {
				return err
			}
			render.Overview(cmd.OutOrStdout(), scans, render.OverviewOptions{
				All:     all,
				Flat:    flat,
				Verbose: verbose,
				Color:   useColor(),
			})
			return nil
		},
	}
	c.Flags().BoolVarP(&all, "all", "a", false, "include closed and filtered ports")
	c.Flags().BoolVar(&flat, "flat", false, "one row per host:port instead of grouped tables")
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "expand NSE script output")
	return c
}

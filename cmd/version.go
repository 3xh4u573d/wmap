package cmd

import (
	"runtime/debug"

	"github.com/spf13/cobra"
)

var version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the wmap version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			v := version
			if v == "dev" {
				if bi, ok := debug.ReadBuildInfo(); ok {
					if m := bi.Main.Version; m != "" && m != "(devel)" {
						v = m
					}
				}
			}
			cmd.Println("wmap " + v)
		},
	}
}

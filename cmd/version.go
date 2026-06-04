package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time by goreleaser via ldflags
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of dockersec",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("dockersec %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

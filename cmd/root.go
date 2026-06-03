package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dockersec",
	Short: "Dockerfile and docker-compose security scanner",
	Long:  "dockersec scans you Docker file and docker-compose file for security issue and bad practices",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

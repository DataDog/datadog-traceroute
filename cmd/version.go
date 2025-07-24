package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\nCommit: %s\nBuild Date: %s\nGo Version: %s\n",
			Version, Commit, Date, runtime.Version())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

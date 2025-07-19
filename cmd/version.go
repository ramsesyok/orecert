/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
const Version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "バージョン表示",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

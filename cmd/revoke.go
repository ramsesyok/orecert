/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// revokeCmd represents the revoke command
var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "証明書失効 & CRL 更新",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("revoke called")
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
}

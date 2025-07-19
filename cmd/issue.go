/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// issueCmd represents the issue command
var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "鍵+CSR+証明書生成",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("issue called")
	},
}

func init() {
	rootCmd.AddCommand(issueCmd)
	issueCmd.Flags().StringP("type", "t", "server", "select issue type")
}

/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// initCaCmd represents the initCa command
var initCaCmd = &cobra.Command{
	Use:   "initCa",
	Short: "ルート CA 鍵 + 証明書生成",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("initCa called")
	},
}

func init() {
	rootCmd.AddCommand(initCaCmd)
}

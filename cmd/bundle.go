/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// bundleCmd represents the bundle command
var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "PEM → P12/JKS 梱包",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("bundle called")
	},
}

func init() {
	rootCmd.AddCommand(bundleCmd)
	bundleCmd.Flags().StringP("type", "t", "all", "select budle type")
}

/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"orecert/internal/issue"
)

// issueCmd represents the issue command
var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "鍵+CSR+証明書生成",
	RunE: func(cmd *cobra.Command, args []string) error {
		typ, _ := cmd.Flags().GetString("type")
		if len(args) != 1 {
			return fmt.Errorf("profile required")
		}
		var cfg issue.Config
		if err := viper.Unmarshal(&cfg); err != nil {
			return err
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var prof issue.Profile
		if err := yaml.Unmarshal(data, &prof); err != nil {
			return err
		}
		return issue.Issue(cfg, prof, typ)
	},
}

func init() {
	rootCmd.AddCommand(issueCmd)
	issueCmd.Flags().StringP("type", "t", "server", "select issue type")
}

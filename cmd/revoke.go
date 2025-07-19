/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"orecert/internal/revoke"
)

// revokeCmd represents the revoke command
var revokeCmd = &cobra.Command{
	Use:   "revoke [profile]",
	Short: "証明書失効 & CRL 更新",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("profile required")
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var prof revoke.Profile
		if err := yaml.Unmarshal(data, &prof); err != nil {
			return err
		}
		var cfg revoke.Config
		if err := viper.Unmarshal(&cfg); err != nil {
			return err
		}
		if err := revoke.Revoke(cfg, prof); err != nil {
			return err
		}
		fmt.Println("✅", filepath.Join("certs", prof.CN, "cert.pem"))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
}

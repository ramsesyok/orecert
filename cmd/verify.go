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

	"orecert/internal/verify"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify [profile]",
	Short: "証明書 & チェーン検証",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("profile required")
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var prof verify.Profile
		if err := yaml.Unmarshal(data, &prof); err != nil {
			return err
		}
		var cfg verify.Config
		if err := viper.Unmarshal(&cfg); err != nil {
			return err
		}
		if err := verify.Verify(cfg, prof); err != nil {
			return err
		}
		fmt.Println("✅", filepath.Join("certs", prof.CN, "cert.pem"))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

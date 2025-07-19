package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"orecert/internal/bundle"
)

// bundleCmd は bundle サブコマンドです
var bundleCmd = &cobra.Command{
	Use:   "bundle [profile]",
	Short: "PEM → P12/JKS 梱包",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("profile required")
		}
		typ, _ := cmd.Flags().GetString("type")
		profileBytes, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var prof struct {
			CN string `yaml:"cn"`
		}
		if err := yaml.Unmarshal(profileBytes, &prof); err != nil {
			return err
		}
		var cfg bundle.Config
		if err := viper.Unmarshal(&cfg); err != nil {
			return err
		}
		if err := bundle.Bundle(cfg, prof.CN, typ); err != nil {
			return err
		}
		fmt.Println("✅", filepath.Join("certs", prof.CN))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(bundleCmd)
	bundleCmd.Flags().StringP("type", "t", "all", "bundle type (pkcs|jks|all)")
}

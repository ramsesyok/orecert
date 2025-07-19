/*
Copyright © 2025 ramsesyok
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"orecert/internal/ca"
)

// initCaCmd represents the initCa command
var initCaCmd = &cobra.Command{
	Use:   "init-ca",
	Short: "ルート CA 鍵 + 証明書生成",
	Long:  `certs/ca/ 配下に自己署名CA証明書と秘密鍵を生成します。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var cfg ca.Config
		if err := viper.Unmarshal(&cfg); err != nil {
			return err
		}
		if err := ca.InitCA(cfg); err != nil {
			return err
		}
		fmt.Println("✅", cfg.CA.Cert)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCaCmd)
}

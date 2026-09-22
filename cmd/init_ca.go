package cmd

import (
	"github.com/spf13/cobra"
	"orecert/internal/ca"
)

func newInitCACommand(cfg *config) *cobra.Command {
	return &cobra.Command{Use: "init-ca", Short: "ルートCA・鍵・CRLを生成", Args: cobra.NoArgs, RunE: func(command *cobra.Command, args []string) error {
		c := ca.Config{DefaultAlgo: cfg.DefaultAlgo, DefaultDays: cfg.DefaultDays, Overwrite: cfg.Overwrite}
		c.CA.Key = cfg.CA.Key
		c.CA.Cert = cfg.CA.Cert
		if err := ca.InitCA(c); err != nil {
			return err
		}
		return success(command, cfg, c.CA.Cert)
	}}
}

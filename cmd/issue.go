package cmd

import (
	"github.com/spf13/cobra"
	"orecert/internal/issue"
	"path/filepath"
)

func newIssueCommand(cfg *config) *cobra.Command {
	var typ string
	command := &cobra.Command{Use: "issue <profile>", Short: "鍵・CSR・証明書を生成", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, args []string) error {
		profile, err := readProfile(args[0])
		if err != nil {
			return err
		}
		c := issue.Config{DefaultAlgo: cfg.DefaultAlgo, DefaultDays: cfg.DefaultDays, Overwrite: cfg.Overwrite}
		c.CA.Key = cfg.CA.Key
		c.CA.Cert = cfg.CA.Cert
		if err := issue.Issue(c, profile, typ); err != nil {
			return err
		}
		return success(command, cfg, filepath.Join("certs", profile.CN, "cert.pem"))
	}}
	command.Flags().StringVarP(&typ, "type", "t", "server", "用途（server|client|both）")
	return command
}

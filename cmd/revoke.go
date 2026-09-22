package cmd

import (
	"github.com/spf13/cobra"
	"orecert/internal/revoke"
	"path/filepath"
)

func revocationConfig(cfg *config) revoke.Config {
	c := revoke.Config{}
	c.CA.Key = cfg.CA.Key
	c.CA.Cert = cfg.CA.Cert
	return c
}
func newRevokeCommand(cfg *config) *cobra.Command {
	return &cobra.Command{Use: "revoke <profile>", Short: "証明書を失効してCRLを更新", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, args []string) error {
		profile, err := readProfile(args[0])
		if err != nil {
			return err
		}
		if err := revoke.Revoke(revocationConfig(cfg), revoke.Profile{CN: profile.CN}); err != nil {
			return err
		}
		return success(command, cfg, filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem"))
	}}
}
func newRefreshCommand(cfg *config) *cobra.Command {
	return &cobra.Command{Use: "refresh-crl", Short: "失効情報を維持してCRLの期限を更新", Args: cobra.NoArgs, RunE: func(command *cobra.Command, args []string) error {
		if err := revoke.Refresh(revocationConfig(cfg)); err != nil {
			return err
		}
		return success(command, cfg, filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem"))
	}}
}

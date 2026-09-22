package cmd

import (
	"github.com/spf13/cobra"
	"orecert/internal/verify"
	"path/filepath"
)

func newVerifyCommand(cfg *config) *cobra.Command {
	var typ, hostname string
	var skipCRL bool
	command := &cobra.Command{Use: "verify <profile>", Short: "用途・チェーン・期限・失効を検証", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, args []string) error {
		profile, err := readProfile(args[0])
		if err != nil {
			return err
		}
		c := verify.Config{Type: typ, DNSName: hostname, SkipCRL: skipCRL}
		c.CA.Cert = cfg.CA.Cert
		if skipCRL {
			command.PrintErrln("WARN: 失効確認を省略します")
		}
		if err := verify.Verify(c, verify.Profile{CN: profile.CN}); err != nil {
			return err
		}
		return success(command, cfg, filepath.Join("certs", profile.CN, "cert.pem"))
	}}
	command.Flags().StringVarP(&typ, "type", "t", "auto", "用途（auto|server|client|both）")
	command.Flags().StringVar(&hostname, "hostname", "", "追加検証するDNS名またはIPアドレス")
	command.Flags().BoolVar(&skipCRL, "skip-crl", false, "失効確認を明示的に省略")
	return command
}

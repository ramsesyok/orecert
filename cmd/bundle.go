package cmd

import (
	"github.com/spf13/cobra"
	"orecert/internal/bundle"
	"orecert/internal/safefile"
	"path/filepath"
	"strings"
)

func newBundleCommand(cfg *config) *cobra.Command {
	var types []string
	var legacy bool
	command := &cobra.Command{Use: "bundle <profile>", Short: "P12・JKSを生成", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, args []string) error {
		profile, err := readProfile(args[0])
		if err != nil {
			return err
		}
		if _, err := safefile.CertificateDir(profile.CN, cfg.CA.Key, cfg.CA.Cert); err != nil {
			return err
		}
		c := bundle.Config{PKCS12Password: cfg.PKCS12Password, Overwrite: cfg.Overwrite, Legacy: legacy, KeyPass: profile.KeyPass}
		c.CA.Cert = cfg.CA.Cert
		if legacy {
			command.PrintErrln("WARN: 旧環境向けの弱い暗号方式を使用します")
		}
		if err := bundle.Bundle(c, profile.CN, strings.Join(types, ",")); err != nil {
			return err
		}
		return success(command, cfg, filepath.Join("certs", profile.CN))
	}}
	command.Flags().StringSliceVarP(&types, "type", "t", []string{"all"}, "形式（pkcs|jks|all、複数指定可）")
	command.Flags().BoolVar(&legacy, "legacy", false, "旧環境向けのPKCS#12暗号方式を使用")
	return command
}

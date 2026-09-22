package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"orecert/internal/issue"
)

type config struct {
	DefaultAlgo    string `yaml:"default_algo"`
	DefaultDays    int    `yaml:"default_days"`
	Overwrite      bool   `yaml:"overwrite"`
	PKCS12Password string `yaml:"pkcs12_password"`
	JSONOutput     bool   `yaml:"json_output"`
	LogLevel       string `yaml:"log_level"`
	CA             struct {
		Key  string `yaml:"key"`
		Cert string `yaml:"cert"`
	} `yaml:"ca"`
}

// Execute は呼び出すたびに独立したコマンドを構築します。
func Execute() {
	command := newRootCommand()
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cfg := new(config)
	var path string
	root := &cobra.Command{Use: "orecert", Short: "自己署名証明書管理ツール", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVarP(&path, "config", "c", ".orecert.yaml", "設定ファイル（相対パスは実行時ディレクトリ基準）")
	root.PersistentPreRunE = func(command *cobra.Command, args []string) error {
		if command.Name() == "version" || command.Name() == "completion" {
			return nil
		}
		loaded, err := loadConfig(path)
		if err != nil {
			return err
		}
		*cfg = loaded
		return nil
	}
	root.AddCommand(newInitCACommand(cfg), newIssueCommand(cfg), newBundleCommand(cfg), newVerifyCommand(cfg), newRevokeCommand(cfg), newRefreshCommand(cfg), newVersionCommand())
	return root
}

func decodeYAML(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return err
	}
	if len(data) > 1024*1024 {
		return errors.New("YAML file exceeds 1 MiB")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("invalid YAML %s: %w", path, err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("YAML must contain a mapping: %s", path)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid YAML %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("only one YAML document is allowed: %s", path)
	}
	return nil
}

func loadConfig(path string) (config, error) {
	cfg := config{DefaultAlgo: "rsa", DefaultDays: 825, PKCS12Password: "prompt:", LogLevel: "info"}
	cfg.CA.Key = "certs/ca/key.pem"
	cfg.CA.Cert = "certs/ca/cert.pem"
	if err := decodeYAML(path, &cfg); err != nil {
		return cfg, err
	}
	if cfg.DefaultDays < 1 || cfg.DefaultDays > 36500 {
		return cfg, errors.New("default_days must be between 1 and 36500")
	}
	if cfg.DefaultAlgo != "rsa" && cfg.DefaultAlgo != "ecdsa" && cfg.DefaultAlgo != "ed25519" {
		return cfg, errors.New("unsupported default_algo")
	}
	if cfg.CA.Key == "" || cfg.CA.Cert == "" {
		return cfg, errors.New("CA paths must not be empty")
	}
	if cfg.PKCS12Password == "" {
		return cfg, errors.New("pkcs12_password must not be empty")
	}
	if cfg.LogLevel != "quiet" && cfg.LogLevel != "info" && cfg.LogLevel != "debug" {
		return cfg, errors.New("unsupported log_level")
	}
	return cfg, nil
}

func readProfile(path string) (issue.Profile, error) {
	var profile issue.Profile
	err := decodeYAML(path, &profile)
	return profile, err
}

func success(command *cobra.Command, cfg *config, paths ...string) error {
	if cfg.JSONOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"cmd": command.Name(), "status": "ok", "files": paths})
	}
	if cfg.LogLevel != "quiet" {
		command.Println("OK", strings.Join(paths, " "))
	}
	return nil
}

package verify

import (
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"orecert/internal/issue"
)

// Config は verify 用設定です。
type Config struct {
	CA struct {
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

// Profile はプロファイルから CN のみを利用します。
type Profile struct {
	CN string `mapstructure:"cn"`
}

// エラー定義
var (
	ErrExpired = errors.New("expired")
	ErrVerify  = errors.New("verify failed")
)

// Verify は証明書と CA のチェーン検証を行います。
func Verify(cfg Config, prof Profile) error {
	if prof.CN == "" || strings.Contains(prof.CN, "..") || strings.ContainsAny(prof.CN, "/\\") {
		return issue.ErrInvalidCN
	}
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}
	certPath := filepath.Join("certs", prof.CN, "cert.pem")
	cert, err := issue.ReadCert(certPath)
	if err != nil {
		return err
	}
	caCert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return ErrExpired
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now()}); err != nil {
		return ErrVerify
	}
	return nil
}

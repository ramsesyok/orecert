package revoke

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"orecert/internal/issue"
	"orecert/internal/safefile"
)

// Config は revoke 用設定です。
type Config struct {
	CA struct {
		Key  string `mapstructure:"key"`
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

// Profile は CN を保持します。
type Profile struct {
	CN string `mapstructure:"cn"`
}

// Revoke は証明書を失効させ CRL を更新します。
func Revoke(cfg Config, prof Profile) error {
	if safefile.ValidateCN(prof.CN) != nil {
		return issue.ErrInvalidCN
	}
	return update(cfg, prof.CN)
}

// Refresh は失効エントリを維持したままCRLを再署名します。
func Refresh(cfg Config) error { return update(cfg, "") }

func update(cfg Config, cn string) error {
	if cfg.CA.Key == "" {
		cfg.CA.Key = filepath.FromSlash("certs/ca/key.pem")
	}
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}
	crlPath := filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem")
	caCert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	if !caCert.IsCA || now.Before(caCert.NotBefore) || !now.Before(caCert.NotAfter) {
		return errors.New("CA is not valid")
	}
	var cert *x509.Certificate
	if cn != "" {
		base, err := safefile.CertificateDir(cn, cfg.CA.Key, cfg.CA.Cert)
		if err != nil {
			return err
		}
		cert, err = issue.ReadCert(filepath.Join(base, "cert.pem"))
		if err != nil {
			return err
		}
		if err := cert.CheckSignatureFrom(caCert); err != nil {
			return err
		}
	}
	keyAny, err := issue.ReadKey(cfg.CA.Key)
	if err != nil {
		return err
	}
	signer, ok := keyAny.(crypto.Signer)
	if !ok {
		return errors.New("ca key is not signer")
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, caCert.RawSubjectPublicKeyInfo) {
		return errors.New("CA key does not match certificate")
	}
	rl, err := ReadCRL(crlPath, caCert, true)
	if err != nil {
		return err
	}
	revoked := rl.RevokedCertificateEntries
	number := big.NewInt(1)
	if rl.Number != nil {
		number = new(big.Int).Add(rl.Number, big.NewInt(1))
	}
	if cert != nil {
		found := false
		for _, entry := range revoked {
			if cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
				found = true
			}
		}
		if !found {
			revoked = append(revoked, x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: now})
		}
	}
	next := now.AddDate(0, 0, 30)
	if next.After(caCert.NotAfter) {
		next = caCert.NotAfter
	}

	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        caCert.SignatureAlgorithm,
		RevokedCertificateEntries: revoked,
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                next,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, signer)
	if err != nil {
		return err
	}
	return safefile.Write([]safefile.File{{Path: crlPath, Data: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), Mode: 0644}}, true)
}

// ReadCRL は署名と発行者を検証します。旧版の空CRLは更新操作だけで受理します。
func ReadCRL(path string, ca *x509.Certificate, allowLegacyEmpty bool) (*x509.RevocationList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid CRL PEM")
	}
	if allowLegacyEmpty && len(block.Bytes) == 0 {
		return &x509.RevocationList{}, nil
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(crl.RawIssuer, ca.RawSubject) {
		return nil, errors.New("CRL issuer mismatch")
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		return nil, err
	}
	return crl, nil
}

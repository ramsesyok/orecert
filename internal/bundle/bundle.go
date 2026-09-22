package bundle

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"orecert/internal/issue"
	"orecert/internal/safefile"
	"orecert/internal/secret"
	"software.sslmate.com/src/go-pkcs12"
)

// Config はバンドル出力・パスワードの設定です。
type Config struct {
	PKCS12Password string `mapstructure:"pkcs12_password"`
	Overwrite      bool   `mapstructure:"overwrite"`
	Legacy         bool
	KeyPass        string
	CA             struct {
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

// Bundle は検証済みの鍵と証明書を、指定された形式でまとめて保存します。
func Bundle(cfg Config, cn, typ string) error {
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}
	base, err := safefile.CertificateDir(cn, cfg.CA.Cert, filepath.Join(filepath.Dir(cfg.CA.Cert), "key.pem"))
	if err != nil {
		return err
	}
	types := map[string]bool{}
	for _, t := range strings.Split(typ, ",") {
		switch t {
		case "pkcs", "jks":
			types[t] = true
		case "all":
			types["pkcs"] = true
			types["jks"] = true
		default:
			return errors.New("unsupported bundle type")
		}
	}
	files := []safefile.File{}
	if types["pkcs"] {
		files = append(files, safefile.File{Path: filepath.Join(base, "bundle.p12"), Mode: 0600})
	}
	if types["jks"] {
		files = append(files, safefile.File{Path: filepath.Join(base, "bundle.jks"), Mode: 0600})
	}
	if err := safefile.Check(files, cfg.Overwrite); err != nil {
		return err
	}
	key, err := secret.ReadKey(filepath.Join(base, "key.pem"), cfg.KeyPass)
	if err != nil {
		return err
	}
	cert, err := readCert(filepath.Join(base, "cert.pem"))
	if err != nil {
		return err
	}
	caCert, err := readCert(cfg.CA.Cert)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("unsupported signing key")
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return errors.New("private key does not match certificate")
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return err
	}
	password, err := secret.Read(cfg.PKCS12Password)
	if err != nil {
		return err
	}
	defer clear(password)
	for i := range files {
		if filepath.Ext(files[i].Path) == ".p12" {
			files[i].Data, err = encodePKCS12(key, cert, caCert, password, cfg.Legacy)
		} else {
			files[i].Data, err = encodeJKS(key, cert, caCert, password)
		}
		if err != nil {
			return err
		}
		defer clear(files[i].Data)
	}
	return safefile.Write(files, cfg.Overwrite)
}

func readCert(path string) (*x509.Certificate, error) { return issue.ReadCert(path) }

func encodePKCS12(key any, cert, ca *x509.Certificate, password []byte, legacy bool) ([]byte, error) {
	// 互換性の広いAES方式を固定し、将来の既定方式変更の影響を避けます。
	encoder := pkcs12.Modern2023.WithIterations(secret.Iterations)
	if legacy {
		encoder = pkcs12.LegacyDES
	}
	return encoder.Encode(key, cert, []*x509.Certificate{ca}, string(password))
}

func encodeJKS(key any, cert, ca *x509.Certificate, password []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	ks := keystore.New()
	entry := keystore.PrivateKeyEntry{CreationTime: time.Now(), PrivateKey: der, CertificateChain: []keystore.Certificate{{Type: "X509", Content: cert.Raw}, {Type: "X509", Content: ca.Raw}}}
	if err := ks.SetPrivateKeyEntry("orecert", entry, password); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := ks.Store(&out, password); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

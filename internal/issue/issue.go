package issue

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"orecert/internal/safefile"
	"orecert/internal/secret"
)

type Config struct {
	DefaultAlgo string `mapstructure:"default_algo"`
	DefaultDays int    `mapstructure:"default_days"`
	Overwrite   bool   `mapstructure:"overwrite"`
	CA          struct {
		Key  string `mapstructure:"key"`
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

// Profile はプロファイルYAMLの内容を表します。
type Profile struct {
	CN         string   `yaml:"cn"`
	SAN        []string `yaml:"san"`
	Algo       string   `yaml:"algo"`
	RSABits    int      `yaml:"rsa_bits"`
	Days       int      `yaml:"days"`
	EncryptKey bool     `yaml:"encrypt_key"`
	KeyPass    string   `yaml:"key_pass"`
}

var (
	ErrInvalidCN   = safefile.ErrInvalidCN
	ErrInvalidType = errors.New("invalid type")
	ErrExists      = safefile.ErrExists
)

// Issue は鍵と証明書を生成します。
func Issue(cfg Config, prof Profile, typ string) error {
	if typ != "server" && typ != "client" && typ != "both" {
		return ErrInvalidType
	}
	if safefile.ValidateCN(prof.CN) != nil {
		return ErrInvalidCN
	}

	if cfg.DefaultAlgo == "" {
		cfg.DefaultAlgo = "rsa"
	}
	if cfg.DefaultDays == 0 {
		cfg.DefaultDays = 825
	}
	if cfg.CA.Key == "" {
		cfg.CA.Key = filepath.FromSlash("certs/ca/key.pem")
	}
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}

	algo := prof.Algo
	if algo == "" {
		algo = cfg.DefaultAlgo
	}
	days := prof.Days
	if days == 0 {
		days = cfg.DefaultDays
	}
	bits := prof.RSABits
	if bits == 0 {
		bits = 2048
	}

	if days < 1 || days > 36500 {
		return errors.New("days must be between 1 and 36500")
	}
	if err := validateSAN(prof.SAN); err != nil {
		return err
	}
	if !prof.EncryptKey && prof.KeyPass != "" {
		return errors.New("key_pass requires encrypt_key: true")
	}
	if _, err := safefile.CertificateDir(prof.CN, cfg.CA.Key, cfg.CA.Cert, filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem")); err != nil {
		return err
	}

	keyPath := filepath.Join("certs", prof.CN, "key.pem")
	csrPath := filepath.Join("certs", prof.CN, "csr.pem")
	certPath := filepath.Join("certs", prof.CN, "cert.pem")
	chainPath := filepath.Join("certs", prof.CN, "fullchain.pem")
	metaPath := filepath.Join("certs", prof.CN, "meta.json")

	files := []safefile.File{{Path: keyPath, Mode: 0600}, {Path: csrPath, Mode: 0644}, {Path: certPath, Mode: 0644}, {Path: chainPath, Mode: 0644}, {Path: metaPath, Mode: 0644}}
	if err := safefile.Check(files, cfg.Overwrite); err != nil {
		return err
	}

	priv, pub, err := GenerateKey(algo, bits)
	if err != nil {
		return err
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: prof.CN},
		DNSNames:       ParseDNS(prof.SAN),
		IPAddresses:    ParseIP(prof.SAN),
		URIs:           ParseURI(prof.SAN),
		EmailAddresses: ParseEmail(prof.SAN),
	}, priv)
	if err != nil {
		return err
	}

	caCert, err := ReadCert(cfg.CA.Cert)
	if err != nil {
		return err
	}
	caKey, err := ReadKey(cfg.CA.Key)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	if !caCert.IsCA || caCert.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(caCert.NotBefore) || !now.Before(caCert.NotAfter) {
		return errors.New("CA is not valid for certificate signing")
	}
	notAfter := now.AddDate(0, 0, days)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber:   randomSerial(),
		Subject:        pkix.Name{CommonName: prof.CN},
		NotBefore:      now,
		NotAfter:       notAfter,
		DNSNames:       ParseDNS(prof.SAN),
		IPAddresses:    ParseIP(prof.SAN),
		URIs:           ParseURI(prof.SAN),
		EmailAddresses: ParseEmail(prof.SAN),
	}
	tmpl.ExtKeyUsage, tmpl.KeyUsage = usageByType(typ, algo)

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return err
	}

	var password []byte
	if prof.EncryptKey {
		source := prof.KeyPass
		if source == "" {
			source = "prompt:"
		}
		password, err = secret.Read(source)
		if err != nil {
			return err
		}
		defer clear(password)
	}
	files[0].Data, err = secret.Encode(priv, prof.EncryptKey, password)
	if err != nil {
		return err
	}
	defer clear(files[0].Data)
	files[1].Data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	files[2].Data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	full := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	files[3].Data = full

	meta := map[string]any{
		"cn":                 prof.CN,
		"type":               typ,
		"algorithm":          AlgoString(algo, bits),
		"fingerprint_sha256": Fingerprint(certDER),
		"not_before":         tmpl.NotBefore.Format(time.RFC3339),
		"not_after":          tmpl.NotAfter.Format(time.RFC3339),
		"san":                prof.SAN,
		"serial_hex":         strings.ToUpper(tmpl.SerialNumber.Text(16)),
		"key_encrypted":      prof.EncryptKey,
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	files[4].Data = metaBytes
	return safefile.Write(files, cfg.Overwrite)
}

func usageByType(t, algo string) ([]x509.ExtKeyUsage, x509.KeyUsage) {
	var eku []x509.ExtKeyUsage
	switch t {
	case "server":
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "both":
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	ku := x509.KeyUsageDigitalSignature
	if algo != "ed25519" && t != "client" {
		ku |= x509.KeyUsageKeyEncipherment
	}
	return eku, ku
}

// ParseDNS は SAN から DNS エントリを抽出します。
func ParseDNS(san []string) []string {
	var out []string
	for _, s := range san {
		if strings.HasPrefix(s, "DNS:") {
			out = append(out, strings.TrimPrefix(s, "DNS:"))
		}
	}
	return out
}

// ParseIP は SAN から IP アドレスを抽出します。
func ParseIP(san []string) []net.IP {
	var out []net.IP
	for _, s := range san {
		if strings.HasPrefix(s, "IP:") {
			if ip := net.ParseIP(strings.TrimPrefix(s, "IP:")); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

// ParseURI は SAN から URI を抽出します。
func ParseURI(san []string) []*url.URL {
	var out []*url.URL
	for _, s := range san {
		if strings.HasPrefix(s, "URI:") {
			if u, err := url.Parse(strings.TrimPrefix(s, "URI:")); err == nil {
				out = append(out, u)
			}
		}
	}
	return out
}

// ParseEmail は SAN からメールアドレスを抽出します。
func ParseEmail(san []string) []string {
	var out []string
	for _, s := range san {
		if strings.HasPrefix(s, "EMAIL:") {
			out = append(out, strings.TrimPrefix(s, "EMAIL:"))
		}
	}
	return out
}

// GenerateKey は指定アルゴリズムで鍵ペアを生成します。
func GenerateKey(algo string, bits int) (any, any, error) {
	switch algo {
	case "rsa", "":
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, nil, errors.New("rsa_bits must be 2048, 3072 or 4096")
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case "ecdsa":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	default:
		return nil, nil, errors.New("unsupported algo")
	}
}

// WriteKey は秘密鍵を PEM 形式で保存します。
func WriteKey(path string, key any) error {
	data, err := secret.Encode(key, false, nil)
	if err != nil {
		return err
	}
	defer clear(data)
	return safefile.Write([]safefile.File{{Path: path, Data: data, Mode: 0600}}, true)
}

// ReadCert は PEM 形式の証明書を読み込みます。
func ReadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("failed to decode pem")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// ReadKey は PEM 形式の秘密鍵を読み込みます。
func ReadKey(path string) (any, error) {
	return secret.ReadKey(path, "")
}

func validateSAN(san []string) error {
	for _, s := range san {
		kind, value, ok := strings.Cut(s, ":")
		if !ok || value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("invalid SAN: %q", s)
		}
		switch kind {
		case "DNS":
			host := strings.TrimPrefix(value, "*.")
			if len(host) > 253 {
				return fmt.Errorf("invalid DNS SAN: %q", s)
			}
			for _, label := range strings.Split(host, ".") {
				if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return fmt.Errorf("invalid DNS SAN: %q", s)
				}
				for _, c := range label {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
						return fmt.Errorf("invalid DNS SAN: %q", s)
					}
				}
			}
		case "IP":
			if net.ParseIP(value) == nil {
				return fmt.Errorf("invalid IP SAN: %q", s)
			}
		case "URI":
			u, err := url.Parse(value)
			if err != nil || u.Scheme == "" {
				return fmt.Errorf("invalid URI SAN: %q", s)
			}
		case "EMAIL":
			if strings.Count(value, "@") != 1 || strings.ContainsAny(value, " \r\n") || strings.HasPrefix(value, "@") || strings.HasSuffix(value, "@") {
				return fmt.Errorf("invalid EMAIL SAN: %q", s)
			}
		default:
			return fmt.Errorf("unsupported SAN type: %q", kind)
		}
	}
	return nil
}

// Fingerprint は証明書 DER から SHA256 指紋を作成します。
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	hexstr := strings.ToUpper(hex.EncodeToString(h[:]))
	var b strings.Builder
	for i := 0; i < len(hexstr); i += 2 {
		if i > 0 {
			b.WriteString(":")
		}
		b.WriteString(hexstr[i : i+2])
	}
	return b.String()
}

// AlgoString はアルゴリズム表示名を返します。
func AlgoString(algo string, bits int) string {
	switch algo {
	case "rsa", "":
		return fmt.Sprintf("RSA-%d", bits)
	case "ecdsa":
		return "ECDSA-P256"
	case "ed25519":
		return "Ed25519"
	default:
		return algo
	}
}

// randomSerial は 128bit のランダムシリアル番号を生成します。
func randomSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

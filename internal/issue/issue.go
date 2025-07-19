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
	CN      string   `mapstructure:"cn"`
	SAN     []string `mapstructure:"san"`
	Algo    string   `mapstructure:"algo"`
	RSABits int      `mapstructure:"rsa_bits"`
	Days    int      `mapstructure:"days"`
}

var (
	ErrInvalidCN   = errors.New("invalid cn")
	ErrInvalidType = errors.New("invalid type")
	ErrExists      = errors.New("files exist and overwrite disabled")
)

// Issue は鍵と証明書を生成します。
func Issue(cfg Config, prof Profile, typ string) error {
	if typ != "server" && typ != "client" && typ != "both" {
		return ErrInvalidType
	}
	if prof.CN == "" || strings.Contains(prof.CN, "..") || strings.ContainsAny(prof.CN, "/\\") {
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

	if err := os.MkdirAll(filepath.Join("certs", prof.CN), 0755); err != nil {
		return err
	}

	keyPath := filepath.Join("certs", prof.CN, "key.pem")
	csrPath := filepath.Join("certs", prof.CN, "csr.pem")
	certPath := filepath.Join("certs", prof.CN, "cert.pem")
	chainPath := filepath.Join("certs", prof.CN, "fullchain.pem")
	metaPath := filepath.Join("certs", prof.CN, "meta.json")

	if !cfg.Overwrite {
		for _, p := range []string{keyPath, csrPath, certPath, chainPath, metaPath} {
			if exists(p) {
				return ErrExists
			}
		}
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

	tmpl := &x509.Certificate{
		SerialNumber:   randomSerial(),
		Subject:        pkix.Name{CommonName: prof.CN},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, days),
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

	if err := WriteKey(keyPath, priv); err != nil {
		return err
	}
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644); err != nil {
		return err
	}
	full := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	if err := os.WriteFile(chainPath, full, 0644); err != nil {
		return err
	}

	meta := map[string]any{
		"cn":                 prof.CN,
		"type":               typ,
		"algorithm":          AlgoString(algo, bits),
		"fingerprint_sha256": Fingerprint(certDER),
		"not_before":         tmpl.NotBefore.Format(time.RFC3339),
		"not_after":          tmpl.NotAfter.Format(time.RFC3339),
		"san":                prof.SAN,
		"serial_hex":         strings.ToUpper(tmpl.SerialNumber.Text(16)),
		"key_encrypted":      false,
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(metaPath, metaBytes, 0644); err != nil {
		return err
	}

	return nil
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
	var block *pem.Block
	switch k := key.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	case ed25519.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	default:
		return errors.New("unknown key type")
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
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
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("failed to decode pem")
	}
	switch blk.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(blk.Bytes)
	default:
		return nil, errors.New("unknown key type")
	}
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

// exists はファイル存在確認を行います。
func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// randomSerial は 128bit のランダムシリアル番号を生成します。
func randomSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

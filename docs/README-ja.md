# orecert

**orecert** は、ローカル開発環境向けに自己署名証明書を生成・管理するためのコマンドラインツールです。

## インストール

Go 1.22 以降が必要です。`go install` でインストールできます。

```bash
go install github.com/yourname/orecert@latest
```

リポジトリを取得してビルドすることもできます。

```bash
git clone https://github.com/yourname/orecert.git
cd orecert
go build
```

## 使い方

orecert は CA を初期化し、YAML プロファイルに基づいてサーバ証明書やクライアント証明書を発行します。

```bash
orecert init-ca -c .orecert.yaml
orecert issue -c .orecert.yaml profiles/localhost.yml
```

### サブコマンド

- `init-ca` – ルート CA 鍵と証明書を生成
- `issue` – プロファイルから鍵・CSR・証明書を作成
- `bundle` – PEM を PKCS#12 または JKS に梱包
- `verify` – 証明書とチェーンを検証
- `revoke` – 証明書を失効し CRL を更新
- `version` – バージョンを表示

### 設定ファイル

`-c` オプションで指定する `.orecert.yaml` に各種設定を書きます。
アルゴリズムや有効日数、梱包時のパスワードなどを定義できます。

例:

```yaml
default_algo: rsa
default_days: 825
overwrite: false
pkcs12_password: prompt:
ca:
  key: certs/ca/key.pem
  cert: certs/ca/cert.pem
```

詳細は [`requirements.md`](requirements.md) を参照してください。英語版 README は [`../README.md`](../README.md) にあります。

## ライセンス

このプロジェクトは Apache 2.0 ライセンスの下で公開されています。

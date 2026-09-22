# orecert 利用ガイド

orecertは自己署名のルートCAを作り、そのCAで試験用サーバ／クライアント証明書を発行するCLIです。PEM、PKCS#12（P12）、JKSを生成します。Go 1.27.1以降でビルドできます。

## ビルドと最小手順

```powershell
go build -o orecert.exe .
./orecert.exe init-ca -c .orecert.yaml
./orecert.exe issue -c .orecert.yaml profiles/localhost.yml -t server
./orecert.exe bundle -c .orecert.yaml profiles/localhost.yml -t all
./orecert.exe verify -c .orecert.yaml profiles/localhost.yml --hostname localhost
```

Linuxでは`go build -o orecert .`でビルドし、`./orecert`を実行します。設定ファイル、CAパス、プロファイル、パスワードファイル、生成物の相対パスはすべて**実行時のカレントディレクトリ基準**です。`-c`省略時はカレントの`.orecert.yaml`を必須で読み込みます。version/helpは設定不要です。

環境変数による設定上書きはしません。設定の不存在・構文不正・未知フィールド・無効値は生成前にエラーとします。

## 設定例

```yaml
default_algo: rsa
default_days: 825
overwrite: false
pkcs12_password: 'prompt:'
ca:
  key: certs/ca/key.pem
  cert: certs/ca/cert.pem
```

`prompt:`は引用符が必要です。値の指定方法は次のとおりです。

- `'prompt:'`: 端末から非エコー入力。空入力は3回まで再試行します。リダイレクトされた標準入力では待機せずエラーになります。
- `'file:password.txt'`: UTF-8ファイルの内容。末尾のLFまたはCRLFを1つだけ除去します。BOMを付けずに保存してください。
- 直接文字列: そのままパスワードに使います。設定に平文の秘密が残るため、通常は対話入力かファイル方式を使用します。

空パスワードは拒否します。パスワードファイルの権限と保管は利用者が管理してください。

`overwrite: false`はCA・証明書・P12/JKSのすべてに適用されます。`true`でのCA再作成は既存CAの交換であり、旧CAが発行した証明書は新CAでは検証できません。CAの交換前にバックアップを取得してください。

## プロファイルと秘密鍵暗号化

```yaml
cn: localhost
san:
  - DNS:localhost
  - IP:127.0.0.1
algo: rsa
rsa_bits: 3072
days: 365
encrypt_key: true
key_pass: 'prompt:'
```

RSA鍵長は2048/3072/4096。ECDSAはP-256、Ed25519も利用できます。RSAを既定とし、利用アプリの対応が分かる場合に他の方式を選択してください。不正なSAN、負の有効日数、CA領域と衝突するCN、出力ルートを抜けるパスは拒否します。証明書の終了日時はCAの終了日時を超えないよう制限します。CNだけではホスト名の検証に使えないため、サーバ用途ではSANを指定してください。

`encrypt_key: true`はPKCS#8＋AES-256-CBCで実際に暗号化します。PBKDF2-HMAC-SHA-256、16バイトsalt、600,000反復を使用します。key_passを省略すると対話入力です。bundle時にも同じプロファイルのkey_passを使って復号します。

`encrypt_key: false`（既定）の秘密鍵は平文PEMです。CA秘密鍵も平文PEMです。Unixでは0600、Windowsでは生成した秘密鍵とバンドルを実行ユーザー／SYSTEMだけがアクセスできるACLで保護します。サービスアカウントへ配備する場合は必要な読み取り権限を別途設定してください。

## 形式の使い分け

| 利用先 | 生成物 |
| --- | --- |
| PEMを読むサーバ | key.pem、cert.pemまたはfullchain.pem |
| WindowsやPKCS#12対応Javaアプリ | bundle.p12（PFXと同系統の形式） |
| JKSを要求するJavaアプリ | bundle.jks（鍵aliasはorecert） |
| 信頼CAの登録 | certs/ca/cert.pem。秘密鍵key.pemを配布しない |

P12はModern2023互換のAES-256-CBC、PBKDF2-HMAC-SHA-256、SHA-256 MAC、600,000反復を既定にします。`bundle --legacy`は旧環境用の3DES形式を明示選択し、警告を出します。JKSは形式固有の古い保護方式を持つため、対応アプリではP12を優先してください。

`-t pkcs`、`-t jks`、`-t all`に対応し、`-t pkcs -t jks`も両形式を出力します。変換前に鍵と証明書の一致、指定CAとの署名関係を検査します。

## 検証と失効

```powershell
./orecert.exe verify profiles/localhost.yml --hostname localhost
./orecert.exe verify profiles/localhost.yml -t server
./orecert.exe revoke profiles/localhost.yml
./orecert.exe refresh-crl
```

verifyはチェーン・期限・用途・ローカルCRLを確認します。用途の既定`auto`は証明書のserver/client EKUから判定します。`-t both`は両用途の検証を要求します。ホスト名／IPアドレスの検証は`--hostname`指定時に追加で行います。

CRLがない・壊れている・署名や発行者が違う・期限切れ・未来の発行日時の場合は失敗します。`--skip-crl`指定時のみ警告付きで失効確認を省略します。CRLの有効期間は30日（CAの有効期限までに制限）です。`refresh-crl`は失効情報を消さずに期限を更新し、revokeの重複実行で同じ証明書を重複登録しません。

各OSやアプリへの信頼CA登録、CRL配布、接続先アプリでの失効確認設定は自動化しません。orecert側で失効させただけでは外部アプリに反映されません。

## 旧版からの移行

1. 既存のCA・証明書・秘密鍵をバックアップします。CAを作り直す必要はありません。
2. 設定内の`pkcs12_password: prompt:`を`pkcs12_password: 'prompt:'`へ直します。
3. 旧版のencrypt_key指定で生成した鍵は平文だった可能性があります。必要に応じて暗号化を有効にして再発行し、旧鍵の扱いを確認してください。
4. 空パスワードまたは`prompt:`／`file:...`そのものがパスワードになっていた旧バンドルは、正しい設定で作り直します。
5. 初期CRLがヘッダだけの旧形式なら`refresh-crl`で署名付きCRLに移行します。有効な既存CRLは失効情報を維持します。欠落したCRLを空リストとして再作成することはしません。バックアップから復元してください。
6. 再生成後、利用先のアプリで読み込みと通信を確認してください。

## 保存と検査

全出力を一時ファイルに準備してから更新し、通常のI/Oエラー時は元のファイルへ戻します。電源断・プロセス強制終了・同じ出力に対する並行実行のトランザクション保証はありません。

```powershell
go test ./... -count=1 "-coverpkg=./..." "-coverprofile=coverage.out"
./scripts/check-coverage.ps1
go vet ./...
```

CIはWindows/Linuxでテスト、全statement coverage 90%以上、govulncheckを実行します。カバレッジ判定はテスト間の重複ブロックを統合して計算します。

json_outputは成功結果を1行JSONで返します。現時点で失敗はテキストと終了コード1です。旧仕様にある詳細な終了コードやJSONエラー形式までは実装していません。

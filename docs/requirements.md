以下は **仕様 v4.2（改訂版）** を、指定いただいた 2 点の修正を反映して **生成 AI 実装用の機能要求仕様書** として再掲したものです。
修正点: **ツール名**: `orecert` / **グローバル設定ファイル名**: `.orecert.yaml`（先頭ドット、拡張子 `.yaml`）。
ソースコードは提示せず、実装要件を網羅します。

---

# 1. 基本情報

| 項目          | 内容                                                                                                                                     |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| ツール名        | **orecert** （「オレオレ証明書」由来）                                                                                                              |
| 目的          | ローカル/開発用途で自己署名 CA・サーバ/クライアント証明書を簡潔かつ再現性高く生成・検証・梱包                                                                                      |
| 実装言語        | Go 1.22+                                                                                                                               |
| CLI フレームワーク | `github.com/spf13/cobra` 前提                                                                                                            |
| 外部ライブラリ     | `software.sslmate.com/src/go-pkcs12`（PKCS#12 エンコード） / `github.com/pavel-v-chernykh/keystore-go/v4`（JKS） / `golang.org/x/term`（パスワード入力） |
| 環境変数        | **一切使用しない**                                                                                                                            |
| 実行形態        | 単一バイナリ `orecert`                                                                                                                       |
| 対象 OS       | Linux / macOS / Windows（パス区切り抽象化）                                                                                                      |

---

# 2. ディレクトリ / ファイル構成（固定）

```
project-root/
├── orecert                 # ビルドされた実行ファイル
├── .orecert.yaml           # グローバル動作設定 (必須)
├── profiles/               # 証明書プロファイル (YAML, 任意個)
│   └── localhost.yml
└── certs/                  # 生成物ルート（自動生成）
    ├── ca/
    │   ├── key.pem
    │   ├── cert.pem
    │   └── crl.pem
    └── <CN>/
        ├── key.pem
        ├── csr.pem
        ├── cert.pem
        ├── fullchain.pem
        ├── bundle.p12
        ├── bundle.jks
        └── meta.json
```

* CA 専用フォルダ: `certs/ca/` 固定。
* 各証明書フォルダ: `certs/<CN>/` 固定。
* プロファイル名と CN は一致する必要はないが、慣習的に合わせると分かりやすい。

---

# 3. グローバル設定ファイル `.orecert.yaml`

（先頭ドット、拡張子は `.yaml`。`orecert` 実行時、原則 `-c` で明示指定。将来的に “暗黙探索” を実装するならカレント→ホームの順で名称 `.orecert.yaml` を探してよいが、本仕様では **必須オプション扱い** として実装。）

## 3.1 キー一覧

| キー                | 型                                          | 既定値                                                      | 説明                        |
| ----------------- | ------------------------------------------ | -------------------------------------------------------- | ------------------------- |
| `default_algo`    | enum(`rsa`,`ecdsa`,`ed25519`)              | `rsa`                                                    | 鍵方式のデフォルト                 |
| `default_days`    | int                                        | 825                                                      | 証明書有効日数                   |
| `overwrite`       | bool                                       | false                                                    | 既存ファイル上書き可否               |
| `pkcs12_password` | string (`prompt:` / `file:<path>` / 直接文字列) | `prompt:`                                                | `bundle` 時パスワード供給         |
| `log_level`       | enum(`quiet`,`info`,`debug`)               | `info`                                                   | ログ閾値                      |
| `json_output`     | bool                                       | false                                                    | true で各コマンド結果を JSON 1 行出力 |
| `ca`              | map                                        | `{ key: "certs/ca/key.pem", cert: "certs/ca/cert.pem" }` | CA ファイルパス。通常は省略可          |

> 省略されたキーは既定値で動作。余計なキーは警告（無視）。

---

# 4. プロファイルファイル `profiles/<name>.yml`

`issue` 対象の証明書属性のみ（用途 `type` は **CLI オプション化** 済みでプロファイルには存在しない）。

| キー            | 必須 | 型 / 例                               | 説明                               |
| ------------- | -- | ----------------------------------- | -------------------------------- |
| `cn`          | ✓  | `localhost`                         | Common Name（フォルダ名に利用）            |
| `san`         | 任意 | `["DNS:localhost","IP:127.0.0.1"]`  | SAN 一覧（未指定なら空）                   |
| `algo`        | 任意 | `rsa`                               | 指定で既定を上書き                        |
| `rsa_bits`    | 任意 | `2048`                              | `algo: rsa` のみ有効（2048/3072/4096） |
| `days`        | 任意 | `825`                               | 個別上書き                            |
| `encrypt_key` | 任意 | `false`                             | true で秘密鍵暗号化 (PKCS#8)            |
| `key_pass`    | 任意 | `prompt:` / `file:...` / 文字列 / null | `encrypt_key=true` 時の取得法         |

**最小例:**

```yaml
cn: localhost
san:
  - DNS:localhost
  - IP:127.0.0.1
```

---

# 5. サブコマンド仕様

| コマンド      | 目的               | 必須引数                               | 主パラメータ      | 出力                                      |                     |                             |
| --------- | ---------------- | ---------------------------------- | ----------- | --------------------------------------- | ------------------- | --------------------------- |
| `init-ca` | ルート CA 鍵 + 証明書生成 | `-c ./.orecert.yaml`               | なし          | `certs/ca/key.pem`, `certs/ca/cert.pem` |                     |                             |
| `issue`   | 鍵+CSR+証明書生成      | `-c ./.orecert.yaml <profile.yml>` | \`-t server | client                                  | both\` (既定: server) | 指定 CN 配下一式                  |
| `bundle`  | PEM → P12/JKS 梱包 | `-c ./.orecert.yaml <profile.yml>` | \`-t pkcs   | jks                                     | all\`（複数指定可）        | `bundle.p12` / `bundle.jks` |
| `verify`  | 証明書 & チェーン検証     | `-c ./.orecert.yaml <profile.yml>` | なし          | 標準出力のみ                                  |                     |                             |
| `revoke`  | 証明書失効 & CRL 更新   | `-c ./.orecert.yaml <profile.yml>` | なし          | `certs/ca/crl.pem` 更新                   |                     |                             |
| `version` | バージョン表示          | なし                                 | なし          | バージョン文字列                                |                     |                             |

## 5.1 `issue` の `-t` と EKU / KeyUsage

| `-t`     | Extended Key Usage     | KeyUsage (RSA/ECDSA)              | KeyUsage (Ed25519) |
| -------- | ---------------------- | --------------------------------- | ------------------ |
| `server` | ServerAuth             | DigitalSignature, KeyEncipherment | DigitalSignature   |
| `client` | ClientAuth             | DigitalSignature                  | DigitalSignature   |
| `both`   | ServerAuth, ClientAuth | DigitalSignature, KeyEncipherment | DigitalSignature   |

* Ed25519 は署名専用のため KeyEncipherment 付与しない。
* `both` はローカル検証簡略化のための開発用ショートカット（本番推奨外）。

## 5.2 `bundle` の `-t`

| 指定     | 生成           | 備考                     |
| ------ | ------------ | ---------------------- |
| `pkcs` | `bundle.p12` | PKCS#12（パスワード必須）       |
| `jks`  | `bundle.jks` | Java KeyStore（同一パスワード） |
| `all`  | 両方           | `-t pkcs -t jks` と同等   |
| 複数指定   | 和集合          | 重複無視                   |

---

# 6. 出力ファイル仕様（固定名）

| パス                         | 内容                                |
| -------------------------- | --------------------------------- |
| `certs/ca/key.pem`         | ルート CA 秘密鍵 (PEM)                  |
| `certs/ca/cert.pem`        | ルート CA 証明書                        |
| `certs/ca/crl.pem`         | CRL（初回は空の PEM with header）        |
| `certs/<CN>/key.pem`       | 秘密鍵（PKCS#1/SEC1 or 暗号化 PKCS#8）    |
| `certs/<CN>/csr.pem`       | CSR                               |
| `certs/<CN>/cert.pem`      | 発行証明書                             |
| `certs/<CN>/fullchain.pem` | `cert.pem` + CA 連鎖（ここでは CA 1 枚想定） |
| `certs/<CN>/bundle.p12`    | PKCS#12（要求時のみ）                    |
| `certs/<CN>/bundle.jks`    | JKS（要求時のみ）                        |
| `certs/<CN>/meta.json`     | メタ情報（下記スキーマ）                      |

### 6.1 `meta.json` スキーマ

```json5
{
  "cn": "localhost",
  "type": "server|client|both",
  "algorithm": "RSA-2048|ECDSA-P256|Ed25519",
  "fingerprint_sha256": "AA:BB:..",
  "not_before": "RFC3339",
  "not_after": "RFC3339",
  "san": ["DNS:localhost","IP:127.0.0.1"],
  "serial_hex": "01A2...",
  "key_encrypted": false
}
```

---

# 7. 標準出力 / エラー出力

| モード                        | 挙動                                                                                                          |
| -------------------------- | ----------------------------------------------------------------------------------------------------------- |
| text（既定）                   | 成功: `✅ certs/<CN>/cert.pem (Expires: YYYY-MM-DD)` など行単位。警告は `WARN:` 前置き。                                    |
| JSON (`json_output: true`) | 各コマンド 1 行 JSON：`{"cmd":"issue","cn":"localhost","status":"ok","files":{"cert":"certs/localhost/cert.pem"}}` |
| エラー時                       | text → `stderr` にメッセージ / JSON モード → `stderr` に `{"status":"error","code":<int>,"error":"..."}`              |
| パスワード入力                    | `prompt:` 指定時、非エコーで取得。空許可しない（再入力 3 回でエラーコード 4）。                                                             |

---

# 8. 終了コード

| コード | 状態                     |
| --: | ---------------------- |
|   0 | 正常終了                   |
|   1 | 設定ファイル読込 / 構文エラー       |
|   2 | 鍵・CSR・証明書生成失敗          |
|   3 | 上書き禁止によるファイル衝突         |
|   4 | パスワード取得 / 復号失敗         |
|   5 | 署名 / 検証 / 変換 / 失効処理エラー |
|  10 | 予期しない内部例外 (panic 復旧)   |

---

# 9. コマンド使用例

```bash
# CA 生成
orecert init-ca -c .orecert.yaml

# サーバ証明書
orecert issue -c .orecert.yaml profiles/localhost.yml -t server

# クライアント証明書
orecert issue -c .orecert.yaml profiles/localhost.yml -t client

# 双方向 (server+client を 1 枚で)
orecert issue -c .orecert.yaml profiles/localhost.yml -t both

# PKCS#12 + JKS バンドル
orecert bundle -c .orecert.yaml profiles/localhost.yml -t all

# 検証 (JSON 出力有効時は 1 行 JSON)
orecert verify -c .orecert.yaml profiles/localhost.yml

# 失効 & CRL 更新
orecert revoke -c .orecert.yaml profiles/localhost.yml
```

---

# 10. 実装上の機能要件

| 項目        | 要件                                                                |
| --------- | ----------------------------------------------------------------- |
| ディレクトリ生成  | 不在なら `certs/`, `certs/ca/`, `certs/<CN>/` を自動作成                   |
| CA 再生成    | 既存 `key.pem` or `cert.pem` があり `overwrite=false` ならコード 3          |
| 鍵生成       | RSA/ECDSA/Ed25519。RSA は `rsa_bits`（既定 2048 or 明示）                 |
| 鍵暗号化      | `encrypt_key=true` のとき `key_pass` 指定方式でパス取得し PKCS#8 (AES-256-GCM) |
| CSR       | `issue` 時に内部で作成して保存                                               |
| 証明書発行     | `x509.CreateCertificate` で CA 署名。Serial 自動（暗号乱数 128bit 推奨）        |
| SAN       | `san` リストを解析：`DNS:` / `IP:` / `URI:` / `EMAIL:` プレフィクス認識          |
| fullchain | `cert.pem` + CA 証明書を単純連結 (PEM)                                    |
| PKCS#12   | `bundle.p12` に鍵+証明書+CA を格納（パスワード必須）                               |
| JKS       | 上記と同じ中身を alias=`orecert`（固定）で格納                                   |
| verify    | `x509.Verify` でチェーン検証、期限判定 (現在時刻 > not\_after でエラーコード 5)          |
| revoke    | 対象 cert の Serial を CRL エントリに追加。CRL の NextUpdate は 30 日後。          |
| meta.json | 冪等出力（再発行で上書き、差分含め最新状態保持）                                          |
| ログ出力      | `log_level` に応じて info/debug 出力。`quiet` では成功行のみ or 完全沈黙（エラー除く）     |
| 後方互換      | プロファイル内に旧 `type:` キーがあれば警告表示し無視（終了コード 0）                          |

---

# 11. バリデーション要件

| 対象                | ルール                  | エラーコード |
| ----------------- | -------------------- | ------ |
| プロファイル `cn`       | 空文字、パス区切り、`..` を含まない | 1      |
| SAN エントリ          | 未知プレフィクス → 警告 (無視)   | 0      |
| `-t` 値 (`issue`)  | 範囲外                  | 1      |
| `-t` 値 (`bundle`) | 範囲外                  | 1      |
| 期限                | `days <= 0` はエラー     | 1      |

---

# 12. JSON 出力スキーマ（共通）

成功:

```json
{
  "cmd": "issue",
  "cn": "localhost",
  "type": "server",
  "status": "ok",
  "files": {
    "cert": "certs/localhost/cert.pem",
    "key": "certs/localhost/key.pem"
  }
}
```

失敗:

```json
{
  "cmd":"issue",
  "cn":"localhost",
  "status":"error",
  "code":5,
  "error":"verification failed: expired"
}
```

---

# 13. ドキュメント更新（実装後必要）

| ファイル             | 内容                              |
| ---------------- | ------------------------------- |
| README.md        | ツール概要 / インストール / 基本例            |
| USAGE.md         | コマンド詳細 / オプション / 例              |
| CHANGELOG.md     | v4.2: `type` CLI オプション化, ツール名変更 |
| meta-schema.json | `meta.json` の JSON Schema（任意）   |

---

# 14. セキュリティ / 非機能

| 項目      | 要件                                     |
| ------- | -------------------------------------- |
| パスワード入力 | 非エコー、Ctrl+C 中断時はメモリ消去（可能な範囲）           |
| メモリ扱い   | パスワード文字列は使用後ゼロ化（byte slice 運用）         |
| 並列実行    | 同一 CN 同時発行は未サポート（ユーザ責務）                |
| 移植性     | CRLF/LF を意識せず PEM 出力は LF 統一            |
| 冪等性     | `issue` 再実行（上書き許可時）で新規 Serial になる（意図的） |


---

## ✅ 最終確認ポイント

1. **ツール名 / 設定ファイル名変更** 反映済み: `orecert`, `.orecert.yaml`
2. `issue` の種別は CLI `-t` で指定（`server|client|both`）
3. プロファイル YAML は最小 `cn` (+ 推奨 SAN) のみで動作
4. `bundle` の形式指定は CLI `-t pkcs|jks|all`
5. 環境変数依存なし / 絶対的に再現性のある出力レイアウト

---

追加で微調整したい点（例えば `meta.json` のフィールド拡張や CRL の NextUpdate ポリシー変更など）があればお知らせください。どう進めますか？

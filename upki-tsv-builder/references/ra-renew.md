# 登録担当者用証明書 更新申請TSV

種別ID: `ra-renew` / 全13列 / Shift-JIS / CR+LF

登録担当者（RA）がUPKIシステムの操作に使うクライアント証明書（発行者: SECOM Passport for Member RSA CA1、証明書プロファイルID `1`）の更新申請。サーバ証明書の更新と違い、**CSR・利用管理者情報は不要**で、DN・プロファイルID・旧証明書シリアル番号の3項目だけを記入する。

## 項目仕様

| # | 項目名 | 必須 | 内容 |
|---|---|---|---|
| 1 | 主体者DN | ○ | **現行証明書のDNと完全一致**させる（更新でDNは変更不可）。`CN,OU,O,L,C` の順、スペースなし（CN内の氏名のスペースは可）。例: `CN=Taro KOKURITSU,OU=example-ra,O=Example University,L=Chiyoda-ku,C=JP` |
| 2 | 証明書プロファイルID | ○ | `1` 固定 |
| 3 | （空欄） | | |
| 4 | 旧証明書シリアル番号 | ○ | **10進数**（エクスポートの「発行・更新申請-シリアル番号」の値をそのまま使う）。受理実績は10進のみ |
| 5–13 | （空欄） | | タブ区切りで列数だけ確保する |

## 実例

受理済みの申請ファイルの形式（値は架空。1行、末尾CR+LF）:

```
CN=Hanako GAKUJUTSU,OU=Example Project,O=Example University,L=Chiyoda-ku,C=JP<TAB>1<TAB><TAB>123456789012345678901234567890123456<TAB>…（以降空欄、計13列）
```

## ファイル名

慣例は `upki_jp_<氏名>_update_<日時>.tsv`（例: `upki_jp_KOKURITSU-Taro_update_20260101120000.tsv`）。日時は `YYYYMMDD` だけでも受理された実績がある。

## 手順

1. ユーザーがUPKIシステムのエクスポートTSV（46列、ヘッダ付き）を持っている場合は、`scripts/ra_from_export.py` でJSONを作る:
   ```bash
   python3 scripts/ra_from_export.py export.tsv -o input.json
   ```
   出力のサマリ（DN・シリアル10進/16進・有効期間）をユーザーに提示して確認を得る。エクスポートが無い場合は、DNとシリアル番号（10進）を聞き取る。
2. `python3 scripts/build_tsv.py input.json -o <ファイル名>.tsv` で生成する。
3. 生成ファイルを提示する。

## 注意

- **更新前後で主体者DNは完全一致しなければならない（ルール）。** 項目1には現行証明書のDNを1文字も変えずに入れる。更新申請でDNを変更することはできない。
- OUなどDNの値は登録担当者ごとに異なる（例: `example-ra`、`Example Project`）。他の人のDNやサンプルに合わせて書き換えない。
- エクスポートには **アクセスPIN** や証明書本体が含まれる。これらを回答に転記しない。ファイルの取り扱いに注意するよう一言添えてよい。
- 失効申請済みのレコード、プロファイルID 1以外のレコードは対象外（`ra_from_export.py` が除外する）。

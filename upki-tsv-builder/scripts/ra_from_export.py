#!/usr/bin/env python3
"""UPKIシステムのエクスポートTSV（発行・更新申請レコード）から、
登録担当者用証明書 更新申請（ra-renew）用の build_tsv.py 入力JSONを作る。

使い方:
    python3 ra_from_export.py export.tsv -o input.json [--summary]

- エクスポートはUTF-8（BOM付き）/ Shift-JIS のどちらでも読める。
- 列はヘッダ名で特定する（主体者DN / 証明書プロファイルID / 発行・更新申請-シリアル番号 など）。
- アクセスPIN・証明書本体・CSRなどは出力しない（画面・JSONに載せない）。
- 失効申請済みのレコードや、プロファイルIDが1以外のレコードは警告して除外する。
"""

import argparse
import csv
import io
import json
import sys

COL_DN = "主体者DN"
COL_PROFILE = "証明書プロファイルID"
COL_SERIAL = "発行・更新申請-シリアル番号"
COL_NOT_AFTER = "発行・更新申請-証明書有効期限"
COL_NOT_BEFORE = "発行・更新申請-証明書有効開始"
COL_REVOKE_ID = "失効申請-申請ID"


def read_rows(path):
    raw = open(path, "rb").read()
    for enc in ("utf-8-sig", "cp932"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        sys.exit("エラー: 文字コードを判別できません（UTF-8 / Shift-JIS のみ対応）。")
    return list(csv.DictReader(io.StringIO(text), delimiter="\t"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("export")
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    rows = read_rows(args.export)
    if not rows or COL_DN not in rows[0] or COL_SERIAL not in rows[0]:
        sys.exit("エラー: エクスポートTSVのヘッダ（主体者DN / 発行・更新申請-シリアル番号）が見つかりません。")

    records, summary = [], []
    for i, r in enumerate(rows, 1):
        dn, prof, serial = r.get(COL_DN, ""), r.get(COL_PROFILE, ""), r.get(COL_SERIAL, "")
        if prof != "1":
            print(f"[行{i}] 警告: プロファイルID {prof} は登録担当者用証明書ではないため除外しました。", file=sys.stderr)
            continue
        if r.get(COL_REVOKE_ID):
            print(f"[行{i}] 警告: 失効申請済みのレコードのため除外しました（{dn}）。", file=sys.stderr)
            continue
        if not serial:
            print(f"[行{i}] 警告: シリアル番号が空のため除外しました（{dn}）。", file=sys.stderr)
            continue
        records.append({"dn": dn, "profile_id": prof, "serial": serial})
        summary.append({"dn": dn, "profile_id": prof, "serial_dec": serial,
                        "serial_hex": "0x%X" % int(serial) if serial.isdigit() else "",
                        "not_before": r.get(COL_NOT_BEFORE, ""),
                        "not_after": r.get(COL_NOT_AFTER, "")})

    if not records:
        sys.exit("エラー: 対象となる登録担当者用証明書のレコードがありません。")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"type": "ra-renew", "records": records}, f, ensure_ascii=False, indent=2)
    print(json.dumps({"records": summary}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

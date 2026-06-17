#!/usr/bin/env python3
"""UPKI申請TSVファイル生成・検証スクリプト

使い方:
    python3 build_tsv.py input.json -o output.tsv [--force]

input.json の形式:
{
  "type": "server-issue",   # server-issue / server-renew / server-revoke /
                            # acme-create / acme-renew / acme-suspend / acme-revoke
  "records": [
    {
      "dn": "CN=www.example.ac.jp,O=Example University,L=Chiyoda-ku,ST=Tokyo,C=JP",
      "profile_id": "3",
      "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...（PEMそのまま、または1行化済みbase64）",
      "serial": "0x112210E261FEC92B",
      "revoke_reason": "4",
      "revoke_comment": "",
      "acme_account_id": "",
      "admin_name": "国立 太郎",
      "admin_dept": "情報基盤センター",
      "admin_mail": "admin@example.ac.jp",
      "fqdn": "www.example.ac.jp",
      "software": "apache2.4",
      "dnsname": "dNSName=www.example.ac.jp,dNSName=web.example.ac.jp"
    }
  ]
}
各レコードには種別に応じて必要なキーのみ入れる。出力はShift-JIS・CR+LF・13列固定。
エラーがある場合はファイルを出力せず終了コード1（--force で警告のみなら強行可能だが、
エラーがある限り出力しない）。
"""

import argparse
import json
import re
import sys
import unicodedata

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

NUM_COLUMNS = 13
MAX_RECORDS = 99
REVOKE_REASONS = {"0", "1", "3", "4", "5"}
PROFILE_IDS = {"3", "11"}

# 種別ごとの 列番号 -> (キー名, 必須か) の対応
SCHEMAS = {
    "server-issue": {
        1: ("dn", True), 2: ("profile_id", True), 7: ("csr", True),
        8: ("admin_name", False), 9: ("admin_dept", False),
        10: ("admin_mail", True), 11: ("fqdn", True),
        12: ("software", True), 13: ("dnsname", False),
    },
    "server-renew": {
        1: ("dn", True), 2: ("profile_id", True), 4: ("serial", True),
        7: ("csr", True), 8: ("admin_name", False), 9: ("admin_dept", False),
        10: ("admin_mail", True), 11: ("fqdn", True),
        12: ("software", True), 13: ("dnsname", False),
    },
    "server-revoke": {
        1: ("dn", True), 4: ("serial", True), 5: ("revoke_reason", True),
        6: ("revoke_comment", False), 10: ("admin_mail", False),
    },
    "acme-create": {
        1: ("dn", True), 2: ("profile_id", True),
        8: ("admin_name", False), 9: ("admin_dept", False),
        10: ("admin_mail", True), 11: ("fqdn", True),
        12: ("software", True), 13: ("dnsname", False),
    },
    "acme-renew": {
        1: ("dn", True), 2: ("profile_id", True), 3: ("acme_account_id", True),
        8: ("admin_name", False), 9: ("admin_dept", False),
        10: ("admin_mail", True), 11: ("fqdn", True),
        12: ("software", True), 13: ("dnsname", False),
    },
    "acme-suspend": {
        1: ("dn", False), 3: ("acme_account_id", True),
        5: ("revoke_reason", True), 6: ("revoke_comment", False),
        10: ("admin_mail", False),
    },
    "acme-revoke": {
        1: ("dn", True), 4: ("serial", True), 5: ("revoke_reason", True),
        6: ("revoke_comment", False), 10: ("admin_mail", False),
    },
}

MAX_LEN = {  # キー名 -> 最大文字数
    "dn": 250, "profile_id": 2, "csr": 2048, "serial": 50,
    "revoke_reason": 1, "revoke_comment": 128, "acme_account_id": 128,
    "admin_name": 64, "admin_dept": 64, "admin_mail": 78,
    "fqdn": 64, "software": 128, "dnsname": 250,
}

FQDN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?$")
MAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
SERIAL_RE = re.compile(r"^(?:\d+|0x[0-9A-Fa-f]+)$")
DN_SPLIT_RE = re.compile(r",(?=\s*(?:CN|OU|O|L|ST|C|E|EMAIL|EMAILADDRESS)\s*=)", re.IGNORECASE)


class Issues:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def err(self, rec_no, msg):
        self.errors.append(f"[レコード{rec_no}] エラー: {msg}")

    def warn(self, rec_no, msg):
        self.warnings.append(f"[レコード{rec_no}] 警告: {msg}")


def parse_dn(dn):
    """'CN=a,O=b,...' を [(属性名(原文), 値), ...] に分解する。値中のカンマは
    次のトークンが '属性名=' で始まらない限り値の一部として扱う。"""
    parts = DN_SPLIT_RE.split(dn)
    parsed = []
    for p in parts:
        if "=" not in p:
            return None
        attr, val = p.split("=", 1)
        parsed.append((attr.strip(), val))
    return parsed


def check_shift_jis(rec_no, key, value, issues):
    try:
        value.encode("shift_jis")
    except UnicodeEncodeError as e:
        bad = value[e.start:e.end]
        issues.err(rec_no, f"{key}: 「{bad}」はShift-JIS（JIS第一・第二水準）で表現できない文字です。"
                           f"第二水準以下の文字に置き換えてください。")


def check_common(rec_no, key, value, issues):
    if "\t" in value or "\n" in value or "\r" in value:
        issues.err(rec_no, f"{key}: タブ・改行は含められません。")
    if key in MAX_LEN and len(value) > MAX_LEN[key]:
        issues.err(rec_no, f"{key}: {MAX_LEN[key]}文字以内にしてください（現在{len(value)}文字）。")
    check_shift_jis(rec_no, key, value, issues)


def validate_dn(rec_no, dn, tsv_type, issues):
    parsed = parse_dn(dn)
    if not parsed:
        issues.err(rec_no, "dn: 「属性名=値」をカンマで区切った形式で記述してください。")
        return None
    attrs = [a for a, _ in parsed]
    upper = [a.upper() for a in attrs]
    values = dict(zip(upper, [v for _, v in parsed]))

    if any(a in ("E", "EMAIL", "EMAILADDRESS") for a in upper):
        issues.err(rec_no, "dn: Email属性は使用できません。")
    if values.get("C") and values["C"] != "JP":
        issues.err(rec_no, "dn: C は JP 固定です。")

    is_acme = tsv_type.startswith("acme")
    if is_acme:
        for a in attrs:
            if a != a.upper():
                issues.err(rec_no, f"dn: 属性名「{a}」は大文字で記述してください（ACME申請は大文字のみ）。")
        if re.search(r"\s=|=\s|,\s", dn):
            issues.err(rec_no, "dn: ACME申請では「=」の前後・「,」の後にスペースを入れられません。")
        if tsv_type != "acme-revoke" and "OU" in upper:
            issues.err(rec_no, "dn: この申請ではOUは使用できません。")
    elif re.search(r"\s=|=\s|,\s", dn):
        issues.warn(rec_no, "dn: 「=」「,」の前後にスペースがあります。CSRのDNと不一致になる恐れがあるため、"
                            "スペースなしでの記述を推奨します。")

    # 順序チェック
    if tsv_type == "acme-revoke":
        # CN,(OU...),O,L/ST,C
        seq = [a for a in upper]
        expected_head = "CN"
        if not seq or seq[0] != expected_head:
            issues.err(rec_no, "dn: 先頭はCNにしてください。")
        core = [a for a in seq if a not in ("OU",)]
        order = {"CN": 0, "O": 1, "L": 2, "ST": 3, "C": 4}
        idx = [order.get(a, -1) for a in core]
        if -1 in idx or idx != sorted(idx):
            issues.err(rec_no, "dn: CN,(OU,)O,L,ST,C の順序で記述してください。")
        if "L" not in upper and "ST" not in upper:
            issues.err(rec_no, "dn: LとSTのどちらかは必須です。")
    elif tsv_type == "acme-suspend":
        order = {"CN": 0, "O": 1, "L": 2, "ST": 3, "C": 4}
        idx = [order.get(a, -1) for a in upper]
        if -1 in idx or idx != sorted(idx):
            issues.err(rec_no, "dn: CN,O,L,ST,C の順序で記述してください。")
        if "L" not in upper and "ST" not in upper:
            issues.err(rec_no, "dn: LとSTのどちらかは必須です。")
    else:
        expected = ["CN", "O", "L", "ST", "C"]
        if upper != expected:
            issues.err(rec_no, f"dn: CN,O,L,ST,C の5項目をこの順序で過不足なく記述してください"
                               f"（現在: {','.join(attrs) if attrs else 'なし'}）。")

    cn = values.get("CN", "")
    if cn and not FQDN_RE.match(cn):
        # サーバ/ACME系のCNはFQDN
        issues.err(rec_no, "dn: CN（FQDN）に使えるのは半角英数と「.」「-」のみで、先頭・末尾の「.」「-」は不可です。")
    if cn and len(cn) > 64:
        issues.err(rec_no, "dn: CNは64文字以内にしてください。")
    return values


def normalize_csr(raw):
    """PEMヘッダ・改行を除去して1行のbase64にする。"""
    body = re.sub(r"-----(BEGIN|END)[^-]*-----", "", raw)
    return "".join(body.split())


def validate_csr(rec_no, raw_csr, profile_id, dn_values, issues):
    one_line = normalize_csr(raw_csr)
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", one_line or ""):
        issues.err(rec_no, "csr: base64として不正な文字が含まれています。PEM形式のCSRを貼り付けてください。")
        return one_line
    if not HAVE_CRYPTO:
        issues.warn(rec_no, "csr: cryptographyライブラリがないため内容検証をスキップしました"
                            "（pip install cryptography で検証可能）。")
        return one_line
    pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + \
          "\n".join(one_line[i:i+64] for i in range(0, len(one_line), 64)) + \
          "\n-----END CERTIFICATE REQUEST-----\n"
    try:
        csr = x509.load_pem_x509_csr(pem.encode())
    except Exception as e:
        issues.err(rec_no, f"csr: CSRとして解析できませんでした（{e}）。")
        return one_line

    key = csr.public_key()
    if profile_id == "3":
        if not isinstance(key, rsa.RSAPublicKey):
            issues.err(rec_no, "csr: プロファイルID 3 はRSA鍵のCSRが必要です。")
        elif key.key_size != 2048:
            issues.err(rec_no, f"csr: RSA鍵長は2048bitにしてください（現在{key.key_size}bit）。")
    elif profile_id == "11":
        if not isinstance(key, ec.EllipticCurvePublicKey):
            issues.err(rec_no, "csr: プロファイルID 11 はECDSA鍵のCSRが必要です。")
        elif key.curve.name != "secp384r1":
            issues.err(rec_no, f"csr: 曲線はsecp384r1にしてください（現在{key.curve.name}）。")

    # CSRのSubjectと項目1のDNを比較
    oid_map = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.7": "L",
               "2.5.4.8": "ST", "2.5.4.6": "C", "2.5.4.11": "OU"}
    csr_attrs = []
    for rdn in csr.subject.rdns:
        for av in rdn:
            csr_attrs.append((oid_map.get(av.oid.dotted_string, av.oid.dotted_string), av.value))
    csr_order = [a for a, _ in csr_attrs]
    fwd = ["C", "ST", "L", "O", "CN"]
    core = [a for a in csr_order if a != "OU"]
    if core != fwd and core != list(reversed(fwd)):
        issues.err(rec_no, f"csr: CSR内のDN順序は C→ST→L→O→CN またはその逆順にしてください"
                           f"（現在: {'→'.join(csr_order)}）。CSRの作り直しが必要です。")
    if dn_values:
        csr_values = dict(csr_attrs)
        for attr in ("CN", "O", "L", "ST", "C"):
            a, b = dn_values.get(attr), csr_values.get(attr)
            if a is not None and b is not None and a != b:
                issues.err(rec_no, f"csr: {attr}の値が項目1のDNと一致しません"
                                   f"（DN側「{a}」/ CSR側「{b}」）。")
    return one_line


def validate_dnsname(rec_no, value, fqdn, is_acme, issues):
    if value.endswith(","):
        issues.err(rec_no, "dnsname: 末尾に「,」を付けないでください。")
        return
    parts = value.split(",")
    hosts = []
    for p in parts:
        if not p.startswith("dNSName="):
            issues.err(rec_no, f"dnsname: 各要素は「dNSName=ホスト名」の形式にしてください（不正: 「{p}」）。")
            return
        host = p[len("dNSName="):]
        if not FQDN_RE.match(host):
            issues.err(rec_no, f"dnsname: ホスト名「{host}」に使えるのは半角英数と「.」「-」のみで、"
                               f"先頭・末尾の「.」「-」は不可です。")
        hosts.append(host)
    if len(hosts) > 8:
        issues.err(rec_no, f"dnsname: 指定できるのは8個までです（現在{len(hosts)}個）。")
    if is_acme and len(hosts) != len(set(hosts)):
        issues.err(rec_no, "dnsname: 重複したホスト名は指定できません。")
    total = len(value)
    if fqdn and fqdn not in hosts:
        total += len(",dNSName=" + fqdn)
        issues.warn(rec_no, f"dnsname: 利用管理者FQDN（{fqdn}）が含まれていないため、システム側で自動付与されます。")
    if total > 250:
        issues.err(rec_no, f"dnsname: 自動付与分を含めて250文字以内にしてください（推定{total}文字）。")


def validate_record(rec_no, rec, tsv_type, issues):
    schema = SCHEMAS[tsv_type]
    out = {}
    valid_keys = {k for _, (k, _) in ((c, kv) for c, kv in schema.items())}
    for k in rec:
        if k not in valid_keys:
            issues.warn(rec_no, f"不明なキー「{k}」は無視します。")

    for col, (key, required) in schema.items():
        value = str(rec.get(key, "") or "").strip()
        if key == "csr":
            value = str(rec.get(key, "") or "").strip()  # CSRはあとで正規化
        if required and not value:
            issues.err(rec_no, f"{key}: 必須項目が未入力です。")
            continue
        if not value:
            out[col] = ""
            continue
        if key != "csr":
            check_common(rec_no, key, value, issues)
        out[col] = value

    dn_values = None
    if out.get(1):
        dn_values = validate_dn(rec_no, out[1], tsv_type, issues)
    if out.get(2) and out[2] not in PROFILE_IDS:
        issues.err(rec_no, "profile_id: 3（RSA）または 11（ECDSA）を指定してください。")
    if "serial" in [schema.get(4, ("", False))[0]] and out.get(4):
        if not SERIAL_RE.match(out[4]):
            issues.err(rec_no, "serial: 10進数、または先頭に0xを付けた16進数で記述してください。")
    if schema.get(5) and out.get(5):
        if out[5] not in REVOKE_REASONS:
            issues.err(rec_no, "revoke_reason: 0 / 1 / 3 / 4 / 5 のいずれかを指定してください。")
        elif out[5] == "1":
            issues.warn(rec_no, "revoke_reason: 1（KeyCompromise）が指定されています。"
                                "秘密鍵の漏洩（または漏洩の恐れ）がある場合以外は絶対に選択しないでください。"
                                "通常の更新に伴う失効は 4（superseded）です。")
    if out.get(10) and not MAIL_RE.match(out[10]):
        issues.err(rec_no, "admin_mail: メールアドレスの形式が正しくありません。")
    if out.get(11):
        if not FQDN_RE.match(out[11]):
            issues.err(rec_no, "fqdn: 半角英数と「.」「-」のみ使用可能で、先頭・末尾の「.」「-」は不可です。")
        if dn_values and dn_values.get("CN") and dn_values["CN"] != out[11]:
            issues.err(rec_no, f"fqdn: 項目1のCN（{dn_values['CN']}）と一致させてください。")
    if schema.get(7) and out.get(7):
        out[7] = validate_csr(rec_no, out[7], out.get(2, ""), dn_values, issues)
        if len(out[7]) > MAX_LEN["csr"]:
            issues.err(rec_no, f"csr: 1行化後{MAX_LEN['csr']}文字以内にしてください（現在{len(out[7])}文字）。")
    if out.get(13):
        validate_dnsname(rec_no, out[13], out.get(11, ""), tsv_type.startswith("acme"), issues)

    return [out.get(c, "") for c in range(1, NUM_COLUMNS + 1)]


def main():
    ap = argparse.ArgumentParser(description="UPKI申請TSV生成・検証")
    ap.add_argument("input", help="入力JSONファイル")
    ap.add_argument("-o", "--output", required=True, help="出力TSVファイルパス（.tsv または .txt）")
    ap.add_argument("--force", action="store_true", help="警告があっても出力する（エラーがある場合は出力しない）")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)

    tsv_type = data.get("type")
    if tsv_type not in SCHEMAS:
        print(f"エラー: type は {', '.join(SCHEMAS)} のいずれかにしてください。", file=sys.stderr)
        sys.exit(1)
    records = data.get("records", [])
    if not records:
        print("エラー: records が空です。", file=sys.stderr)
        sys.exit(1)

    issues = Issues()
    if len(records) > MAX_RECORDS:
        issues.errors.append(f"エラー: 申請は1ファイル{MAX_RECORDS}件までです（現在{len(records)}件）。分割してください。")

    rows = [validate_record(i + 1, rec, tsv_type, issues) for i, rec in enumerate(records)]

    for w in issues.warnings:
        print(w)
    for e in issues.errors:
        print(e, file=sys.stderr)

    if issues.errors:
        print(f"\n{len(issues.errors)}件のエラーがあるためファイルは出力しませんでした。", file=sys.stderr)
        sys.exit(1)
    if issues.warnings and not args.force:
        print(f"\n{len(issues.warnings)}件の警告があります。内容を確認のうえ、問題なければ --force を付けて再実行してください。")
        sys.exit(2)

    content = "".join("\t".join(row) + "\r\n" for row in rows)
    with open(args.output, "wb") as f:
        f.write(content.encode("shift_jis"))

    print(f"OK: {len(rows)}件 / {NUM_COLUMNS}列 / Shift-JIS / CR+LF で出力しました -> {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""稼働中サーバの証明書情報を取得し、TSV事前入力用JSONを出力する

使い方:
    # 方法1: サーバに直接接続して取得（ネットワーク制限下では失敗することがある）
    python3 inspect_server.py --host www.example.ac.jp [--port 443]

    # 方法2: 証明書PEM（または openssl s_client の出力全体）を貼り付けたファイルから解析
    python3 inspect_server.py --pem cert.txt

    # 方法2の取得例（ユーザーのサーバ・端末で実行してもらう）:
    #   openssl s_client -connect www.example.ac.jp:443 -servername www.example.ac.jp \
    #     </dev/null 2>/dev/null | openssl x509

出力: 人間向けサマリ（stderr）と、build_tsv.py の records にそのまま使える
事前入力JSON（stdout）。
"""

import argparse
import json
import re
import socket
import ssl
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

OID_MAP = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.7": "L",
           "2.5.4.8": "ST", "2.5.4.6": "C", "2.5.4.11": "OU"}


def fetch_cert(host, port, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 期限切れ・チェーン不備でも情報取得を優先
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)


def load_pem(path):
    raw = open(path, "r", encoding="utf-8", errors="replace").read()
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                  raw, re.DOTALL)
    if not m:
        sys.exit("エラー: ファイル内に -----BEGIN CERTIFICATE----- 形式の証明書が見つかりません。\n"
                 "openssl s_client の出力をそのまま貼った場合は、証明書ブロックが含まれているか確認してください。")
    return x509.load_pem_x509_certificate(m.group(0).encode())


def name_to_attrs(name):
    attrs = []
    for rdn in name.rdns:
        for av in rdn:
            attrs.append((OID_MAP.get(av.oid.dotted_string, av.oid.dotted_string), av.value))
    return attrs


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--host", help="対象サーバのFQDN（URLではなくホスト名）")
    g.add_argument("--pem", help="証明書PEMを含むファイル")
    ap.add_argument("--port", type=int, default=443)
    args = ap.parse_args()

    if args.host:
        host = re.sub(r"^https?://", "", args.host).split("/")[0].split(":")[0]
        try:
            cert = fetch_cert(host, args.port)
        except Exception as e:
            sys.exit(f"接続エラー: {host}:{args.port} から証明書を取得できませんでした（{e}）。\n"
                     f"この環境からの外部接続が制限されている可能性があります。代わりに以下のコマンドの出力を\n"
                     f"ファイルに保存し、--pem で指定してください:\n"
                     f"  openssl s_client -connect {host}:{args.port} -servername {host} </dev/null 2>/dev/null | openssl x509")
        issuer_cn_check = dict(name_to_attrs(cert.issuer)).get("CN", "")
        subj_cn_check = dict(name_to_attrs(cert.subject)).get("CN", "")
        if re.search(r"egress|gateway|proxy", issuer_cn_check, re.IGNORECASE) or \
           re.search(r"egress|gateway|proxy", subj_cn_check, re.IGNORECASE):
            sys.exit(f"中断: 取得した証明書はネットワークプロキシが差し替えたもの（発行者: {issuer_cn_check}）の\n"
                     f"可能性が高く、本物のサーバ証明書ではありません。この情報は使用できません。\n"
                     f"以下のコマンドを対象サーバに到達できる端末で実行し、出力をファイルに保存して --pem で指定してください:\n"
                     f"  openssl s_client -connect {host}:{args.port} -servername {host} </dev/null 2>/dev/null | openssl x509")
    else:
        cert = load_pem(args.pem)

    subj = dict(name_to_attrs(cert.subject))
    issuer = dict(name_to_attrs(cert.issuer))

    # SANs
    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc = f"RSA {key.key_size}bit"
        profile = "3"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc = f"ECDSA {key.curve.name}"
        profile = "11"
    else:
        key_desc = type(key).__name__
        profile = ""

    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    serial_hex = f"0x{cert.serial_number:X}"

    cn = subj.get("CN", "")
    dn_parts = []
    for a in ("CN", "O", "L", "ST", "C"):
        if a in subj:
            dn_parts.append(f"{a}={subj[a]}")
    dn = ",".join(dn_parts)
    missing = [a for a in ("CN", "O", "L", "ST", "C") if a not in subj]

    issuer_cn = issuer.get("CN", "(不明)")
    is_upki = "NII Open Domain" in issuer_cn

    dnsname = ",".join(f"dNSName={h}" for h in sans) if sans else ""

    # ---- 人間向けサマリ ----
    print(f"対象: {cn or '(CNなし)'}", file=sys.stderr)
    print(f"  発行者         : {issuer_cn}" + ("  ← UPKI(NII)発行の証明書です" if is_upki else "  ※UPKI発行ではない可能性があります"), file=sys.stderr)
    print(f"  主体者DN       : {dn}", file=sys.stderr)
    if "OU" in subj:
        print(f"  （OUあり: {subj['OU']} — 現行仕様ではOUは使用不可のため、新DNからは除外が必要）", file=sys.stderr)
    if missing:
        print(f"  （DNに {','.join(missing)} がありません — 申請時は機関の届出値で補完が必要）", file=sys.stderr)
    print(f"  シリアル番号   : {serial_hex}", file=sys.stderr)
    print(f"  有効期限       : {not_after:%Y-%m-%d} （残り{days_left}日）" + ("  ⚠期限切れ" if days_left < 0 else "  ⚠30日未満" if days_left < 30 else ""), file=sys.stderr)
    print(f"  鍵             : {key_desc} → 推奨プロファイルID: {profile or '不明'}", file=sys.stderr)
    print(f"  SANs           : {', '.join(sans) if sans else '(なし)'}", file=sys.stderr)

    # ---- 事前入力JSON ----
    prefill = {
        "cert_summary": {
            "issuer_cn": issuer_cn, "is_upki_issued": is_upki,
            "not_after": f"{not_after:%Y-%m-%d}", "days_left": days_left,
            "key": key_desc, "has_ou": "OU" in subj, "missing_dn_attrs": missing,
        },
        "server_renew_prefill": {
            "dn": dn, "profile_id": profile, "serial": serial_hex,
            "fqdn": cn, "dnsname": dnsname,
        },
        "acme_create_prefill": {
            "dn": dn, "profile_id": profile, "fqdn": cn, "dnsname": dnsname,
        },
        "server_revoke_prefill": {
            "dn": dn, "serial": serial_hex, "revoke_reason": "4",
        },
    }
    json.dump(prefill, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()

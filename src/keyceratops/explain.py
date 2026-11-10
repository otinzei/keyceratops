"""Human-facing wording: what each check means and what to do about it.

Kept apart from the checks so that the detection logic stays language-free and
so a translation can be added without touching it. Languages: ``ja``, ``en``.
"""

from __future__ import annotations

import os
from typing import Mapping

from .model import Finding, Severity

LANGS = ("ja", "en")


def detect_language(env: Mapping[str, str] | None = None) -> str:
    """``ja`` when the locale says Japanese, otherwise ``en``."""
    env = os.environ if env is None else env
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        value = env.get(var, "")
        if value:
            return "ja" if value.lower().startswith("ja") else "en"
    return "en"


SEVERITY_LABEL = {
    "ja": {
        Severity.CRITICAL: "重大", Severity.HIGH: "高", Severity.MEDIUM: "中",
        Severity.LOW: "低", Severity.INFO: "情報",
    },
    "en": {
        Severity.CRITICAL: "CRITICAL", Severity.HIGH: "HIGH", Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW", Severity.INFO: "INFO",
    },
}

UI = {
    "ja": {
        "banner": "keyceratops {version} — 乱数不良の監査",
        "scanned": "対象: {files}ファイル{skipped}・鍵 {keys}・証明書 {certs}・署名 {sigs}",
        "skipped": "（リンクなどの重複 {n} 件を除外）",
        "verdict": "判定",
        "verdict_action": "要対応",
        "verdict_review": "要確認",
        "verdict_minor": "軽微な指摘のみ",
        "verdict_clean": "問題は見つかりませんでした",
        "start": "まず見る",
        "count": "{n}件",
        "what": "何が問題か",
        "todo": "どうするか",
        "note": "注意",
        "found": "該当",
        "keys": "鍵",
        "where": "場所",
        "more_items": "… ほか {n} 件（-v で全部表示）",
        "more_places": "ほか{n}",
        "base": "※ 場所は {root} からの相対パス",
        "caveat": "※ 「問題なし」は安全の証明ではありません。この検査が見るのは、公開データに痕跡が残る乱数不良だけです。",
        "inputs": "読み込めなかった入力",
        "private_skipped": "秘密鍵ファイルは読まずにスキップ: {n}件",
        "hashed": "ホスト名ハッシュ化",
        "tip_never": "終了コードを常に0にするには --fail-on never",
        "software": "ソフト",
        "attr_title": "原因の手がかり（問題のあるホストに偏っているソフト・機種）",
        "attr_row": "{label}: {a}/{n}台が該当（それ以外は {ao}/{no}台）",
        "attr_p": "p={p}",
        "attr_sig": "偏りは偶然では説明しにくい",
        "attr_weak": "台数が少なく、偶然の可能性もある",
        "attr_note": "※ 偏りは調べる手がかりで、原因の証明ではありません。",
        "attr_none": "ソフト・機種の情報: {n}台分（偏りは見つかりませんでした）",
        "dim_firmware": "ファームウェア", "dim_model": "機種", "dim_vendor": "メーカー",
        "dim_software": "SSHソフト", "dim_product": "SSH製品", "dim_cert-org": "証明書の組織名",
        "pq_title": "量子耐性の棚卸し",
        "pq_summary": "鍵 {keys}（耐量子 {safe}）・証明書 {certs}・通信路 {eps}（耐量子の鍵交換 {pqeps}）",
        "pq_head": "アルゴリズム / 鍵の数 / 現在の強度 / 量子計算機",
        "pq_row": "{name}: {keys}個 / {bits} / {q}",
        "pq_bits": "{n}ビット相当", "pq_bits_none": "不明", "pq_bits_zero": "80ビット未満",
        "pq_broken_by_q": "破られる", "pq_safe": "耐性あり（NISTカテゴリ{lvl}）",
        "pq_prio": "移行の優先順位",
        "prio_broken": "すでに壊れている鍵（上の指摘）",
        "prio_weak": "今の時点でも弱い（112ビット未満、SHA-1/MD5署名の証明書）",
        "prio_long-lived": "2030年末より後まで有効な、量子に弱い証明書",
        "prio_harvest": "耐量子の鍵交換がない通信路（今の通信を記録され、将来解読されうる）",
        "pq_example": "例",
        "pq_deadline": "※ 期限は NIST IR 8547：量子に弱い方式は2030年末で非推奨、2035年末で禁止。",
        "pq_hint": "量子耐性の棚卸し: 鍵 {keys}（耐量子 {safe}）。詳細は --pqc、CBOM は -f cbom",
        "c_notice": "※ 自分が管理している、または許可を得たサーバーだけを指定してください。",
        "c_target": "収集中: {label}",
        "c_done": "完了: 対象 {targets} ・ 証明書 {certs} ・ SSH鍵 {keys} ・ 署名 {sigs}（新規分） → {out}",
        "c_unverified": "  注意: 検証できなかった署名 {n} 件（r, s のみ記録）",
        "c_errors": "取得できなかったもの:",
        "c_next": "次:  keyceratops scan {out}",
        "c_more": "ヒント: 署名は接続ごとに1つ。--samples を増やすと nonce の検査が強くなります。",
    },
    "en": {
        "banner": "keyceratops {version} — randomness audit",
        "scanned": "Scanned: {files} file(s){skipped} · {keys} key(s) · {certs} certificate(s) · {sigs} signature(s)",
        "skipped": " ({n} duplicate path(s) skipped)",
        "verdict": "Verdict",
        "verdict_action": "ACTION NEEDED",
        "verdict_review": "REVIEW",
        "verdict_minor": "MINOR ISSUES ONLY",
        "verdict_clean": "NO PROBLEMS FOUND",
        "start": "Start with",
        "count": "{n}",
        "what": "What is wrong",
        "todo": "What to do",
        "note": "Note",
        "found": "Found",
        "keys": "keys",
        "where": "where",
        "more_items": "... and {n} more (use -v to show all)",
        "more_places": "+{n} more",
        "base": "(paths are relative to {root})",
        "caveat": "Note: 'no problems' is not proof of soundness. This audit only sees randomness failures that leave a trace in public data.",
        "inputs": "Inputs that could not be read",
        "private_skipped": "Private key files skipped unread: {n}",
        "hashed": "hashed host name",
        "tip_never": "use --fail-on never for a zero exit status",
        "software": "software",
        "attr_title": "Leads (software / models over-represented among affected hosts)",
        "attr_row": "{label}: {a} of {n} affected (others: {ao} of {no})",
        "attr_p": "p={p}",
        "attr_sig": "unlikely to be chance",
        "attr_weak": "few hosts; could be chance",
        "attr_note": "Note: an over-represented label is a lead to investigate, not proof of a cause.",
        "attr_none": "software / model labels: {n} holder(s) (no over-representation found)",
        "dim_firmware": "firmware", "dim_model": "model", "dim_vendor": "vendor",
        "dim_software": "SSH software", "dim_product": "SSH product", "dim_cert-org": "certificate organisation",
        "pq_title": "Post-quantum inventory",
        "pq_summary": "{keys} key(s) ({safe} quantum-safe) · {certs} certificate(s) · {eps} endpoint(s) ({pqeps} with post-quantum key exchange)",
        "pq_head": "algorithm / keys / strength today / quantum computer",
        "pq_row": "{name}: {keys} / {bits} / {q}",
        "pq_bits": "{n}-bit", "pq_bits_none": "unknown", "pq_bits_zero": "below 80-bit",
        "pq_broken_by_q": "broken", "pq_safe": "resistant (NIST category {lvl})",
        "pq_prio": "Migration priorities",
        "prio_broken": "already broken (see findings above)",
        "prio_weak": "weak today (below 112-bit, or SHA-1/MD5-signed certificate)",
        "prio_long-lived": "quantum-vulnerable certificates valid past the end of 2030",
        "prio_harvest": "endpoints without post-quantum key exchange (recorded traffic can be decrypted later)",
        "pq_example": "e.g.",
        "pq_deadline": "Deadlines: NIST IR 8547 deprecates quantum-vulnerable algorithms after 2030 and disallows them after 2035.",
        "pq_hint": "post-quantum inventory: {keys} key(s), {safe} quantum-safe. Details: --pqc; CBOM: -f cbom",
        "c_notice": "Only collect from servers you own or are authorised to test.",
        "c_target": "collecting: {label}",
        "c_done": "done: {targets} target(s) · {certs} certificate(s) · {keys} SSH key(s) · {sigs} signature(s) (new) -> {out}",
        "c_unverified": "  note: {n} signature(s) did not verify (only r, s recorded)",
        "c_errors": "not collected:",
        "c_next": "next:  keyceratops scan {out}",
        "c_more": "tip: one signature per connection; raise --samples for stronger nonce checks.",
    },
}

NOTES = {
    "alias_or_clone": {
        "ja": "known_hosts だけでは「同じサーバーの別名（ホスト名とIPなど）」か「複製された機器」か区別できません。"
              "別名でないか確認してください。",
        "en": "known_hosts cannot tell one server under two names (hostname and IP) from cloned machines. "
              "Check that these are not simply aliases first.",
    },
}

# check id -> title / meaning / advice, per language
CHECKS: dict[str, dict[str, dict[str, str]]] = {
    "rsa-roca": {
        "title": {"ja": "Infineon製ライブラリの欠陥RSA鍵（ROCA）", "en": "Infineon RSALib key (ROCA)"},
        "meaning": {
            "ja": "Infineon の RSALib が作った鍵に特有の構造があります（CVE-2017-15361）。素数の作り方に偏りがあり、"
                  "公開鍵だけから、同じ長さの普通の鍵よりはるかに少ない計算量で素因数分解できます。"
                  "原因はこのライブラリを積んだTPM・ICカード・セキュリティキー（2017年の修正前のもの）です。",
            "en": "The modulus has the structure of keys made by Infineon's RSALib (CVE-2017-15361). Its prime "
                  "generation is biased, so the key can be factored from the public key at a cost far below a "
                  "normal key of the same size. The cause is a TPM, smart card or security key with that library "
                  "(made before the 2017 fix).",
        },
        "advice": {
            "ja": "鍵を作った機器のファームウェアを更新するか機器を交換し、鍵を作り直して古い鍵を失効させる。"
                  "鍵の長さを延ばすだけでは直らない。",
            "en": "Update the firmware of (or replace) the device that generated the key, then generate a new key "
                  "and revoke the old one. A longer key from the same library is not a fix.",
        },
    },
    "shared-prime": {
        "title": {"ja": "RSA鍵が素数を共有している", "en": "RSA keys share a prime factor"},
        "meaning": {
            "ja": "公開鍵だけから秘密鍵を計算できる状態です。独立に作った鍵は素数を共有しません。"
                  "素数を作る時点で乱数の状態が同じだった（起動直後のエントロピー不足など）ことを示します。",
            "en": "Anyone can compute the private keys from the public keys alone. Independent keys never share a prime; "
                  "this means the random generator was in the same state when the primes were drawn "
                  "(typically low entropy at first boot).",
        },
        "advice": {
            "ja": "該当する鍵はすべて漏えい扱いにして失効・再発行する。再発行の前に、機器の乱数源（起動直後のエントロピー）を直す。",
            "en": "Treat every listed key as compromised: revoke and re-issue. Fix the device's entropy source before re-issuing.",
        },
    },
    "ecdsa-nonce-reuse": {
        "title": {"ja": "ECDSAのnonceを使い回している", "en": "ECDSA nonce reused"},
        "meaning": {
            "ja": "同じ鍵で作った2つの署名が同じnonceを使っています。2つの署名とメッセージのハッシュから、秘密鍵を計算できます。",
            "en": "Two signatures by the same key used the same nonce. The private key follows from the two signatures "
                  "and their message hashes.",
        },
        "advice": {
            "ja": "その鍵は漏えい扱いで失効・再発行する。署名側の乱数生成を見直す（RFC 6979 の決定的nonceの採用も有効）。",
            "en": "Treat the key as compromised: revoke and re-issue. Review the signer's randomness "
                  "(deterministic nonces per RFC 6979 also help).",
        },
    },
    "duplicate-key": {
        "title": {"ja": "同じ鍵が複数の場所で使われている", "en": "The same key is used in several places"},
        "meaning": {
            "ja": "複数の機器が同じ秘密鍵を持っている可能性があります。出荷時の共通鍵、またはどの機器も同じ乱数出力を作ってしまう状態が典型です。"
                  "1台から鍵を取り出せば、全台になりすませます。",
            "en": "Several devices may hold the same private key: a factory-default key, or a generator that produced the same "
                  "output on every unit. Extracting the key from one unit lets an attacker impersonate all of them.",
        },
        "advice": {
            "ja": "まず、本当に別々の機器か確認する（同じ機器の別名・コピー・更新前後の証明書なら問題ありません）。"
                  "別々の機器なら、機器ごとに鍵を作り直す。",
            "en": "First check that these really are different devices (aliases, copies and renewals of one device are fine). "
                  "If they are different devices, generate a fresh key per device.",
        },
    },
    "common-modulus": {
        "title": {"ja": "同じ法を指数違いで使っている", "en": "RSA modulus reused with different exponents"},
        "meaning": {
            "ja": "同じ法（n）を使う鍵ペアの持ち主は、他の鍵の秘密指数を計算できます。",
            "en": "The holder of one key pair can derive the private exponent of the others.",
        },
        "advice": {"ja": "鍵ペアごとに独立した素数から作り直す。", "en": "Regenerate each pair from its own primes."},
    },
    "rsa-even": {
        "title": {"ja": "RSAの法が偶数", "en": "RSA modulus is even"},
        "meaning": {
            "ja": "2で割り切れるため、自明に素因数分解できます。鍵生成プログラムのバグです。",
            "en": "Divisible by 2, so trivially factored. A key generation bug.",
        },
        "advice": {"ja": "鍵を破棄して再生成し、生成ツールを調べる。", "en": "Discard and regenerate; investigate the generator."},
    },
    "rsa-small-factor": {
        "title": {"ja": "RSAの法が小さな素因数を持つ", "en": "RSA modulus has a small prime factor"},
        "meaning": {
            "ja": "2^16未満の素因数があり、自明に素因数分解できます。正常な鍵生成では起きません。",
            "en": "A prime factor below 2^16 makes it trivially factorable. A healthy generator never produces this.",
        },
        "advice": {"ja": "鍵を破棄して再生成し、生成ツールを調べる。", "en": "Discard and regenerate; investigate the generator."},
    },
    "rsa-square": {
        "title": {"ja": "RSAの法が平方数（p = q）", "en": "RSA modulus is a perfect square (p = q)"},
        "meaning": {
            "ja": "2つの素数が同じ値です。乱数源が固まっている（同じ値を返し続ける）可能性があります。",
            "en": "Both primes are identical, which points to a stuck or exhausted random source.",
        },
        "advice": {"ja": "鍵を再生成し、乱数源の動作を確認する。", "en": "Regenerate and check the random source."},
    },
    "rsa-close-primes": {
        "title": {"ja": "RSAの2つの素数が近すぎる", "en": "RSA primes are too close together"},
        "meaning": {
            "ja": "Fermat法で素因数分解できました。2つ目の素数を1つ目から作っている、または乱数の質が極端に低い可能性があります。",
            "en": "Fermat's method factored the modulus. The second prime was likely derived from the first, "
                  "or the random source is extremely poor.",
        },
        "advice": {"ja": "鍵を再生成し、鍵生成コードを確認する。", "en": "Regenerate and review the key generation code."},
    },
    "rsa-tiny": {
        "title": {"ja": "RSA鍵が1024ビット未満", "en": "RSA key shorter than 1024 bits"},
        "meaning": {
            "ja": "現実的な計算量で素因数分解できる長さです。",
            "en": "Short enough to be factored with modest resources.",
        },
        "advice": {"ja": "2048ビット以上で再生成する。", "en": "Regenerate with at least 2048 bits."},
    },
    "rsa-short": {
        "title": {"ja": "RSA鍵が推奨より短い", "en": "RSA key shorter than recommended"},
        "meaning": {
            "ja": "現在の推奨強度（2048ビット）を下回っています。",
            "en": "Below the current minimum strength (2048 bits).",
        },
        "advice": {"ja": "更新の際に2048ビット以上で再生成する。", "en": "Regenerate with at least 2048 bits at the next renewal."},
    },
    "rsa-bad-exponent": {
        "title": {"ja": "RSAの公開指数が不正", "en": "Invalid RSA public exponent"},
        "meaning": {
            "ja": "公開指数は3以上の奇数でなければなりません。",
            "en": "A public exponent must be odd and at least 3.",
        },
        "advice": {"ja": "鍵を再生成する。", "en": "Regenerate the key."},
    },
    "rsa-low-exponent": {
        "title": {"ja": "RSAの公開指数が65537より小さい", "en": "RSA public exponent below 65537"},
        "meaning": {
            "ja": "規格上は有効ですが、標準は65537です。古い鍵生成器や独自実装でよく見られます。",
            "en": "Valid, but 65537 is the standard choice; small exponents often come from legacy or hand-rolled generators.",
        },
        "advice": {"ja": "緊急ではありません。更新の機会に65537で再生成する。", "en": "Not urgent. Regenerate with 65537 at the next renewal."},
    },
    "ecdsa-shared-r": {
        "title": {"ja": "別々の鍵で署名値rが重複している", "en": "Same ECDSA r under different keys"},
        "meaning": {
            "ja": "別々の鍵の署名でrが一致するのは、偶然ではまず起きません（確率は約2^-256）。複数の機器の乱数が同じ状態にあったことを示します。"
                  "この時点で鍵は漏れていませんが、どれかの機器が同じnonceを2回使うと秘密鍵が漏れます。",
            "en": "Equal r under different keys essentially never happens by chance (about 2^-256): the devices' generators "
                  "were in the same state. No key is exposed yet, but any device that also repeats a nonce leaks its key.",
        },
        "advice": {
            "ja": "該当機器の署名用の乱数源を調べる。署名を追加で集め、nonceの再利用がないか確認する。",
            "en": "Investigate those devices' signing randomness. Collect more signatures and look for nonce reuse.",
        },
    },
    "ecdsa-biased-nonce": {
        "title": {"ja": "ECDSAのnonceに偏りの疑い", "en": "ECDSA nonce looks biased"},
        "meaning": {
            "ja": "rが群の位数より32ビット以上短いのは、偶然では2^-32の確率です。nonceに偏りがあると、多数の署名から格子攻撃で秘密鍵を復元できる場合があります。",
            "en": "An r at least 32 bits shorter than the group order has chance 2^-32. Biased nonces can allow lattice attacks "
                  "that recover the key from many signatures.",
        },
        "advice": {"ja": "nonceの生成方法を確認する（決定的nonceの採用を検討）。", "en": "Check how nonces are generated (consider deterministic nonces)."},
    },
    "serial-collision": {
        "title": {"ja": "同じ発行者で同じシリアル番号", "en": "Duplicate serial under one issuer"},
        "meaning": {
            "ja": "シリアル番号は発行者の中で一意でなければなりません。64ビット以上の長いシリアルが重複するのは、偶然ではなく乱数状態の再現を強く示します。",
            "en": "Serials must be unique per issuer. A collision among long serials is a strong sign of a repeated random state.",
        },
        "advice": {"ja": "発行ツールのシリアル生成を確認する。", "en": "Check the issuing tool's serial generation."},
    },
    "serial-short": {
        "title": {"ja": "シリアル番号が64ビット未満", "en": "Serial number shorter than 64 bits"},
        "meaning": {
            "ja": "2016-09-30以降、公開信頼されるTLS証明書には、CSPRNG由来の64ビット以上のシリアルが必要です（CA/Browser Forum）。"
                  "それ以前に発行された証明書は判定していません。",
            "en": "Since 2016-09-30, publicly trusted TLS certificates need serials with at least 64 bits from a CSPRNG "
                  "(CA/Browser Forum). Certificates issued before that date are not judged.",
        },
        "advice": {
            "ja": "プライベートPKIなら緊急ではありません。発行ツールを更新し、長いランダムなシリアルにする。",
            "en": "Not urgent for a private PKI. Update the issuing tool to use long random serials.",
        },
    },
    "serial-predictable": {
        "title": {"ja": "シリアル番号が予測しやすい", "en": "Predictable serial numbers"},
        "meaning": {
            "ja": "連番、または変化の少ないシリアルです。プライベートCAでカウンタを使うのは問題ありませんが、公開信頼CAでは規則に反します。",
            "en": "Sequential or low-variability serials. Fine for a private CA using a counter, "
                  "but not allowed for publicly trusted CAs.",
        },
        "advice": {
            "ja": "公開CAなら修正が必要。プライベートCAなら、方針として許容できるか判断する。",
            "en": "Must be fixed for a public CA. For a private CA, decide whether a counter is acceptable.",
        },
    },
    "serial-invalid": {
        "title": {"ja": "シリアル番号が正の整数でない", "en": "Serial number is not a positive integer"},
        "meaning": {
            "ja": "RFC 5280 ではシリアル番号は正の整数です。古いルート証明書には違反するものがあり、そちらは実害のない歴史的な不備です。",
            "en": "RFC 5280 requires a positive integer. Some old roots violate this; harmless there, "
                  "but a defect in a recently issued certificate.",
        },
        "advice": {
            "ja": "最近発行された証明書なら発行元に連絡する。古いルート証明書は無視してよい。",
            "en": "Contact the issuer if the certificate is recent. Ignore it for old roots.",
        },
    },
}


def check_text(check: str, lang: str) -> tuple[str, str, str]:
    """(title, meaning, advice) for a check id; falls back to the id."""
    entry = CHECKS.get(check)
    if entry is None:
        return check, "", ""
    return (entry["title"][lang], entry["meaning"][lang], entry["advice"][lang])


def advice_en(check: str) -> str:
    entry = CHECKS.get(check)
    return entry["advice"]["en"] if entry else ""


def instance_label(f: Finding, lang: str) -> str:
    """One line describing a single finding of a check."""
    d, ja = f.data, lang == "ja"
    c = f.check
    try:
        if c == "shared-prime":
            return (f"{d['keys']}個の鍵が素数を共有（{d['bits']}ビット）" if ja
                    else f"{d['keys']} keys share a prime ({d['bits']}-bit)")
        if c == "duplicate-key":
            algo = str(d.get("algorithm", "")).upper()
            bits = f" {d['bits']}ビット" if ja and d.get("bits") else (f" {d['bits']}-bit" if d.get("bits") else "")
            return (f"{d['holders']}か所で同じ{algo}鍵{('（' + bits.strip() + '）') if bits else ''}" if ja
                    else f"same {algo} key{bits} in {d['holders']} places")
        if c == "common-modulus":
            return (f"{d['keys']}個の鍵が同じ法（{d['bits']}ビット）" if ja
                    else f"{d['keys']} keys on one modulus ({d['bits']}-bit)")
        if c == "ecdsa-nonce-reuse":
            return (f"署名{d['signatures']}件で同じnonce" if ja
                    else f"{d['signatures']} signatures with the same nonce")
        if c == "ecdsa-shared-r":
            return (f"{d['repeated_r']}個のrが複数の鍵で重複" if ja
                    else f"{d['repeated_r']} r value(s) repeated across keys")
        if c == "ecdsa-biased-nonce":
            return (f"署名{d['signatures']}件でrが小さすぎる" if ja
                    else f"{d['signatures']} signature(s) with implausibly small r")
        if c == "rsa-close-primes":
            return (f"{d['count']}個の鍵（素数の差は約2^{d['log2_prime_distance_max']}）" if ja
                    else f"{d['count']} key(s) (prime distance about 2^{d['log2_prime_distance_max']})")
        if c == "rsa-roca":
            return (f"{d['count']}個の鍵（最大{d['bits_max']}ビット）" if ja
                    else f"{d['count']} key(s) (up to {d['bits_max']}-bit)")
        if c.startswith("rsa-"):
            return f"{d['count']}個の鍵" if ja else f"{d['count']} key(s)"
        if c == "serial-collision":
            return (f"発行者 {d['issuer']} のシリアルが{d['certificates']}枚で重複（{d['serial_bits']}ビット・鍵{d['distinct_keys']}種）" if ja
                    else f"issuer {d['issuer']}: {d['certificates']} certificates share a {d['serial_bits']}-bit serial ({d['distinct_keys']} keys)")
        if c == "serial-short":
            ex = d.get("exempt_before_2016_09_30", 0)
            extra = (f"（2016-09-30より前の{ex}枚は対象外）" if ja else f" ({ex} older than 2016-09-30 not judged)") if ex else ""
            return (f"{d['count']}枚{extra}" if ja else f"{d['count']} certificate(s){extra}")
        if c == "serial-predictable":
            kind = ("連番" if d["sequential"] else f"変化するビットは{d['varying_bits']}個") if ja else (
                "sequential" if d["sequential"] else f"only {d['varying_bits']} varying bits")
            return (f"発行者 {d['issuer']} の{d['certificates']}枚（{kind}）" if ja
                    else f"issuer {d['issuer']}: {d['certificates']} certificates ({kind})")
        if c == "serial-invalid":
            return f"{d['count']}枚" if ja else f"{d['count']} certificate(s)"
    except KeyError:
        pass
    return f.title

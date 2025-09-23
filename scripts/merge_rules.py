#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import yaml
import hashlib
import urllib.request
from urllib.error import URLError, HTTPError
from collections import OrderedDict, defaultdict

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(REPO_ROOT, "config", "rule-sources.yaml")
OUTPUT_DIR = os.path.join(REPO_ROOT, "rule")

COMMENT_LINE_RE = re.compile(r'^\s*#')
INLINE_COMMENT_RE = re.compile(r'\s+#.*$')

# 粗略识别规则类型（仅用于 allow_types 过滤；不做严苛校验）
RULE_TYPE_RE = re.compile(r'^\s*([A-Z\-]+)\s*,')
VALID_RULE_PREFIXES = {
    "DOMAIN","DOMAIN-SUFFIX","DOMAIN-KEYWORD","IP-CIDR","IP-CIDR6",
    "GEOIP","IP-ASN","PROCESS-NAME","URL-REGEX","RULE-SET"
}

def read_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def fetch_url(url):
    with urllib.request.urlopen(url, timeout=30) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")

def read_local(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def normalize_line(line, trim_inline=False, normalize_ws=True):
    s = line.rstrip("\n\r")
    if trim_inline:
        s = INLINE_COMMENT_RE.sub("", s)
    if normalize_ws:
        s = re.sub(r'\s+', ' ', s).strip()
    else:
        s = s.strip()
    return s

def rule_type_of(line):
    m = RULE_TYPE_RE.match(line)
    if not m:
        return None
    return m.group(1)

def iter_rules_from_text(text, strip_comments, trim_inline, normalize_ws, allow_types):
    for raw in text.splitlines():
        if COMMENT_LINE_RE.match(raw) or not raw.strip():
            continue
        line = normalize_line(raw, trim_inline=trim_inline, normalize_ws=normalize_ws)
        if not line:
            continue

        if allow_types:
            t = rule_type_of(line)
            if t is None or t not in allow_types:
                continue
        yield line

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def write_text(path, content):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

def sha256_str(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]

def main():
    if not os.path.exists(CONFIG_PATH):
        print(f"[ERROR] config not found: {CONFIG_PATH}", file=sys.stderr)
        sys.exit(1)

    cfg = read_yaml(CONFIG_PATH) or {}
    sources = cfg.get("sources", [])
    options = cfg.get("options", {}) or {}

    sort = bool(options.get("sort", False))
    deduplicate = options.get("deduplicate", True) is not False
    normalize_ws = options.get("normalize_whitespace", True) is not False
    fail_on_missing = bool(options.get("fail_on_missing", False))
    delete_orphans = options.get("delete_orphan_outputs", True) is not False

    # label -> ordered rule list
    merged = defaultdict(list)

    # 为去重准备：label -> OrderedSet（用 dict 充当）
    seen = defaultdict(OrderedDict)

    # 收集当前周期应当产出的 label 名单
    labels_expected = set()

    for idx, src in enumerate(sources, 1):
        label = src.get("label")
        if not label:
            print(f"[WARN] source[{idx}] missing 'label', skipped.", file=sys.stderr)
            continue
        labels_expected.add(label)

        url = src.get("url")
        path = src.get("path")

        strip_comments = bool(src.get("strip_comments", False))
        trim_inline = bool(src.get("trim_inline_comments", False))
        allow_types = src.get("allow_types")
        if allow_types:
            allow_types = [t for t in allow_types if t in VALID_RULE_PREFIXES]

        try:
            if url:
                content = fetch_url(url)
                origin = f"url:{url}"
            elif path:
                real = os.path.join(REPO_ROOT, path) if not os.path.isabs(path) else path
                if not os.path.exists(real):
                    msg = f"[{'ERROR' if fail_on_missing else 'WARN'}] local file not found: {real}"
                    print(msg, file=sys.stderr)
                    if fail_on_missing:
                        sys.exit(2)
                    else:
                        continue
                content = read_local(real)
                origin = f"path:{path}"
            else:
                print(f"[WARN] source[{idx}] missing 'url' or 'path', skipped.", file=sys.stderr)
                continue
        except (HTTPError, URLError, TimeoutError) as e:
            msg = f"[{'ERROR' if fail_on_missing else 'WARN'}] fetch failed ({label}): {e}"
            print(msg, file=sys.stderr)
            if fail_on_missing:
                sys.exit(3)
            else:
                continue

        cnt_before = 0
        cnt_after = 0
        for rule in iter_rules_from_text(
            content,
            strip_comments=strip_comments,
            trim_inline=trim_inline,
            normalize_ws=normalize_ws,
            allow_types=allow_types
        ):
            cnt_before += 1
            if deduplicate:
                if rule in seen[label]:
                    continue
                seen[label][rule] = True
            merged[label].append(rule)
            cnt_after += 1

        print(f"[INFO] merged '{label}' <= {origin}  rules: {cnt_after}/{cnt_before}")

    ensure_dir(OUTPUT_DIR)

    # 清理孤儿输出（label 已不在配置中）
    if delete_orphans:
        for fname in os.listdir(OUTPUT_DIR):
            if not fname.endswith(".list"):
                continue
            lab = fname[:-5]
            if lab not in labels_expected:
                os.remove(os.path.join(OUTPUT_DIR, fname))
                print(f"[INFO] removed orphan output: {fname}")

    # 写入输出
    for label, rules in merged.items():
        content_rules = sorted(rules) if sort else rules
        header = [
            f"# label: {label}",
            f"# count: {len(content_rules)}",
            f"# build: merge_rules.py",
            ""
        ]
        body = "\n".join(content_rules) + ("\n" if content_rules else "")
        output = "\n".join(header) + body

        out_path = os.path.join(OUTPUT_DIR, f"{label}.list")
        write_text(out_path, output)

        print(f"[INFO] wrote {out_path}  sha:{sha256_str(output)}  lines:{len(content_rules)}")

    # 若某些 label 没有任何来源或全部失败，仍写空文件（便于下游感知“变为空了”）
    for lab in labels_expected:
        out_path = os.path.join(OUTPUT_DIR, f"{lab}.list")
        if not os.path.exists(out_path):
            write_text(out_path, "# empty\n")
            print(f"[INFO] wrote empty {out_path}")

if __name__ == "__main__":
    main()

"""JVN と JVN iPedia の RSS を取得し、照合済みの JSON を出力する。

使い方:
    uv run scripts/fetch.py                      # 直近7日分を data/items.json に出力
    uv run scripts/fetch.py --days 14 --min-cvss 7.0
    uv run scripts/fetch.py --from-file tests/fixtures/jvn.rdf tests/fixtures/jvndb_new.rdf
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

JVN_URL = "https://jvn.jp/rss/jvn.rdf"
IPEDIA_URL = "https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf"
USER_AGENT = "jvn-podcast-digest/0.1 (+https://github.com/AstroMev/jvn-podcast-digest)"
TIMEOUT_SEC = 30
RETRY_WAIT_SEC = 2
SUMMARY_MAX_CHARS = 300

NS = {
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/",
}

Item = dict[str, Any]


# ---------------------------------------------------------------------------
# 取得
# ---------------------------------------------------------------------------


def fetch_bytes(url: str) -> bytes:
    """URL を取得する。失敗したら1回だけリトライする。"""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as res:
                return res.read()
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == 1:
                raise
            print(f"warn: {url} の取得に失敗しました（{e}）。リトライします", file=sys.stderr)
            time.sleep(RETRY_WAIT_SEC)
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# パース
# ---------------------------------------------------------------------------


def _text(el: ET.Element, path: str) -> str:
    found = el.find(path, NS)
    return (found.text or "").strip() if found is not None else ""


def _parse_date(value: str) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).isoformat()
    except ValueError:
        return None


def clean_summary(text: str) -> str:
    """HTML タグと余分な空白を取り除き、長すぎる場合は切り詰める。"""
    text = re.sub(r"<[^>]+>", " ", html.unescape(text))
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > SUMMARY_MAX_CHARS:
        text = text[:SUMMARY_MAX_CHARS].rstrip() + "…"
    return text


def pick_cvss(cvss_list: list[dict[str, Any]]) -> dict[str, Any] | None:
    """複数の CVSS から代表を1つ選ぶ。v3 系を優先し、同じ系統ならスコアの高いもの。"""
    if not cvss_list:
        return None
    return max(cvss_list, key=lambda c: (c["version"].startswith("3"), c["score"]))


def parse_jvn(xml_bytes: bytes) -> list[Item]:
    """JVN 新着/更新フィード（jvn.rdf）をパースする。"""
    root = ET.fromstring(xml_bytes)
    items = []
    for el in root.findall("rss:item", NS):
        items.append(
            {
                "source": "jvn",
                "id": _text(el, "dc:identifier"),
                "title": _text(el, "rss:title"),
                "summary": clean_summary(_text(el, "rss:description")),
                "url": _text(el, "rss:link"),
                "published": _parse_date(_text(el, "dcterms:issued") or _text(el, "dc:date")),
                "modified": _parse_date(_text(el, "dcterms:modified")),
                "cves": [],
                "cvss": None,
                "products": [],
                "related": [],
            }
        )
    return items


def parse_ipedia(xml_bytes: bytes) -> list[Item]:
    """JVN iPedia 新着フィード（jvndb_new.rdf）をパースする。

    `related` には、この項目が参照している JVN の ID（JVNVU#... など）が入る。
    """
    root = ET.fromstring(xml_bytes)
    items = []
    for el in root.findall("rss:item", NS):
        cves: list[str] = []
        jvn_refs: list[str] = []
        for ref in el.findall("sec:references", NS):
            source = ref.get("source")
            ref_id = ref.get("id", "")
            if source == "CVE" and ref_id not in cves:
                cves.append(ref_id)
            elif source == "JVN" and ref_id not in jvn_refs:
                jvn_refs.append(ref_id)

        cvss_list = []
        for c in el.findall("sec:cvss", NS):
            try:
                score = float(c.get("score", ""))
            except ValueError:
                continue
            cvss_list.append(
                {
                    "version": c.get("version", ""),
                    "score": score,
                    "severity": c.get("severity", ""),
                }
            )

        products = []
        for cpe in el.findall("sec:cpe", NS):
            product = {"vendor": cpe.get("vendor", ""), "product": cpe.get("product", "")}
            if product not in products:
                products.append(product)

        items.append(
            {
                "source": "ipedia",
                "id": _text(el, "sec:identifier"),
                "title": _text(el, "rss:title"),
                "summary": clean_summary(_text(el, "rss:description")),
                "url": _text(el, "rss:link"),
                "published": _parse_date(_text(el, "dcterms:issued") or _text(el, "dc:date")),
                "modified": _parse_date(_text(el, "dcterms:modified")),
                "cves": cves,
                "cvss": pick_cvss(cvss_list),
                "products": products,
                "related": jvn_refs,
            }
        )
    return items


# ---------------------------------------------------------------------------
# 照合・絞り込み
# ---------------------------------------------------------------------------


def dedupe(items: list[Item]) -> list[Item]:
    """ID が同じ項目は最初の1件だけ残す。"""
    seen: set[str] = set()
    result = []
    for item in items:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        result.append(item)
    return result


def enrich_jvn(jvn_items: list[Item], ipedia_items: list[Item]) -> None:
    """iPedia 側の JVN 参照を使って、JVN 項目に CVE・CVSS・製品を付ける（その場で更新）。"""
    by_jvn_id: dict[str, list[Item]] = {}
    for ip in ipedia_items:
        for ref in ip["related"]:
            by_jvn_id.setdefault(ref, []).append(ip)

    for item in jvn_items:
        matches = by_jvn_id.get(item["id"], [])
        if not matches:
            continue
        cvss_list = []
        for ip in matches:
            item["related"].append(ip["id"])
            for cve in ip["cves"]:
                if cve not in item["cves"]:
                    item["cves"].append(cve)
            for product in ip["products"]:
                if product not in item["products"]:
                    item["products"].append(product)
            if ip["cvss"]:
                cvss_list.append(ip["cvss"])
        item["cvss"] = pick_cvss(cvss_list)


def filter_recent(items: list[Item], days: int, now: datetime) -> list[Item]:
    """公開日または更新日が直近 `days` 日以内の項目だけを残す。"""
    since = now - timedelta(days=days)
    result = []
    for item in items:
        dates = [d for d in (item["published"], item["modified"]) if d]
        if any(datetime.fromisoformat(d) >= since for d in dates):
            result.append(item)
    return result


def filter_min_cvss(items: list[Item], min_cvss: float) -> list[Item]:
    """CVSS スコアが `min_cvss` 以上の項目だけを残す（CVSS なしは除外）。"""
    return [i for i in items if i["cvss"] and i["cvss"]["score"] >= min_cvss]


def latest_date(items: list[Item]) -> datetime | None:
    dates = [datetime.fromisoformat(d) for i in items for d in (i["published"], i["modified"]) if d]
    return max(dates) if dates else None


def build(
    jvn_xml: bytes,
    ipedia_xml: bytes | None,
    *,
    days: int,
    min_cvss: float | None,
    now: datetime,
) -> dict[str, Any]:
    """2つのフィードから出力用の dict を組み立てる。"""
    jvn_items = dedupe(parse_jvn(jvn_xml))
    ipedia_items = dedupe(parse_ipedia(ipedia_xml)) if ipedia_xml else []

    # 照合は日付で絞る前に行う（古い iPedia 項目にも CVE 情報があるため）
    enrich_jvn(jvn_items, ipedia_items)

    jvn_items = filter_recent(jvn_items, days, now)
    ipedia_items = filter_recent(ipedia_items, days, now)
    if min_cvss is not None:
        ipedia_items = filter_min_cvss(ipedia_items, min_cvss)

    jvn_items.sort(key=lambda i: i["published"] or "", reverse=True)
    ipedia_items.sort(key=lambda i: i["cvss"]["score"] if i["cvss"] else -1, reverse=True)

    return {
        "generated_at": datetime.now(UTC).astimezone().isoformat(timespec="seconds"),
        "reference_time": now.isoformat(timespec="seconds"),
        "days": days,
        "min_cvss": min_cvss,
        "counts": {"jvn": len(jvn_items), "ipedia": len(ipedia_items)},
        "notice": "RSS の内容は配信時点のものです。最新情報は JVN またはベンダーのサイトで確認してください。",
        "items": jvn_items + ipedia_items,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def format_line(item: Item) -> str:
    """選別しやすいように、1項目を1行にまとめる。"""
    cvss = item["cvss"]
    severity = f"{cvss['severity']} {cvss['score']}" if cvss else "-"
    vendors = ", ".join(sorted({p["vendor"] for p in item["products"] if p["vendor"]}))
    return "\t".join([item["source"], item["id"], severity, (item["published"] or "")[:10], item["title"], vendors])


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="JVN / JVN iPedia の RSS を取得して照合済み JSON を出力する")
    p.add_argument("--days", type=int, default=7, help="直近 N 日の項目だけを残す（デフォルト: 7）")
    p.add_argument("--min-cvss", type=float, default=None, help="iPedia 側を CVSS スコアで足切りする")
    p.add_argument("--out", type=Path, default=Path("data/items.json"), help="出力先（デフォルト: data/items.json）")
    p.add_argument(
        "--from-file",
        nargs=2,
        type=Path,
        metavar=("JVN_RDF", "IPEDIA_RDF"),
        help="ネットワークを使わず、保存済みの XML を読む。期間は XML 内の最新日時を基準にする",
    )
    p.add_argument("--list", action="store_true", help="1項目1行の一覧も標準出力に出す（選別用）")
    p.add_argument("--save-raw", type=Path, metavar="DIR", help="取得した XML を DIR に保存する（fixtures 作成用）")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    ipedia_xml: bytes | None
    if args.from_file:
        jvn_xml = args.from_file[0].read_bytes()
        ipedia_xml = args.from_file[1].read_bytes()
    else:
        try:
            jvn_xml = fetch_bytes(JVN_URL)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"error: JVN フィードを取得できませんでした（{e}）。", file=sys.stderr)
            print("       オフラインの場合は --from-file で保存済みの XML を指定してください。", file=sys.stderr)
            return 1
        try:
            ipedia_xml = fetch_bytes(IPEDIA_URL)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"warn: iPedia フィードを取得できませんでした（{e}）。JVN だけで続けます。", file=sys.stderr)
            ipedia_xml = None
        if args.save_raw:
            args.save_raw.mkdir(parents=True, exist_ok=True)
            (args.save_raw / "jvn.rdf").write_bytes(jvn_xml)
            if ipedia_xml:
                (args.save_raw / "jvndb_new.rdf").write_bytes(ipedia_xml)

    now = datetime.now(UTC).astimezone()
    if args.from_file:
        now = latest_date(parse_jvn(jvn_xml) + parse_ipedia(ipedia_xml)) or now

    result = build(jvn_xml, ipedia_xml, days=args.days, min_cvss=args.min_cvss, now=now)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    c = result["counts"]
    if args.list:
        for item in result["items"]:
            print(format_line(item))
    print(f"{args.out} に出力しました（JVN {c['jvn']}件 / iPedia {c['ipedia']}件、直近{args.days}日）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

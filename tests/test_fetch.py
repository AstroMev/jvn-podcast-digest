import json
from datetime import datetime
from pathlib import Path

import fetch
import pytest

FIXTURES = Path(__file__).parent / "fixtures"
JVN_XML = (FIXTURES / "jvn.rdf").read_bytes()
IPEDIA_XML = (FIXTURES / "jvndb_new.rdf").read_bytes()
NOW = datetime.fromisoformat("2026-10-09T12:00:00+09:00")

SMALL_JVN = b"""<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/"
  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/">
 <item rdf:about="https://jvn.jp/vu/JVNVU00000001/">
  <title>Example Router</title>
  <link>https://jvn.jp/vu/JVNVU00000001/</link>
  <description>example</description>
  <dc:identifier>JVNVU#00000001</dc:identifier>
  <dcterms:issued>2026-10-08T10:00:00+09:00</dcterms:issued>
  <dcterms:modified>2026-10-08T10:00:00+09:00</dcterms:modified>
 </item>
 <item rdf:about="https://jvn.jp/vu/JVNVU00000001/">
  <title>Example Router (duplicate)</title>
  <link>https://jvn.jp/vu/JVNVU00000001/</link>
  <dc:identifier>JVNVU#00000001</dc:identifier>
  <dcterms:issued>2026-10-08T10:00:00+09:00</dcterms:issued>
 </item>
 <item rdf:about="https://jvn.jp/jp/JVN00000002/">
  <title>Old item</title>
  <link>https://jvn.jp/jp/JVN00000002/</link>
  <dc:identifier>JVN#00000002</dc:identifier>
  <dcterms:issued>2026-08-01T10:00:00+09:00</dcterms:issued>
  <dcterms:modified>2026-08-01T10:00:00+09:00</dcterms:modified>
 </item>
</rdf:RDF>
"""

SMALL_IPEDIA = """<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/"
  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:sec="http://jvn.jp/rss/mod_sec/">
 <item rdf:about="https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html">
  <title>ルーターの脆弱性</title>
  <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
  <description>&lt;ul&gt;&lt;li&gt;一行目&lt;/li&gt;&#13;
  &lt;li&gt;二行目&lt;/li&gt;&lt;/ul&gt;</description>
  <sec:identifier>JVNDB-2026-000001</sec:identifier>
  <sec:references source="CVE" id="CVE-2026-0001">https://www.cve.org/</sec:references>
  <sec:references source="NVD" id="CVE-2026-0001">https://nvd.nist.gov/</sec:references>
  <sec:references source="JVN" id="JVNVU#00000001">https://jvn.jp/vu/JVNVU00000001/</sec:references>
  <sec:references title="XSS(CWE-79)" id="CWE-79">https://cwe.mitre.org/</sec:references>
  <sec:cpe version="2.2" vendor="Example" product="Router A">cpe:/h:example:a</sec:cpe>
  <sec:cvss version="2.0" score="9.3" type="Base" severity="High" vector="AV:N"/>
  <sec:cvss version="3.0" score="6.1" type="Base" severity="Medium" vector="CVSS:3.0/AV:N"/>
  <dcterms:issued>2026-10-08T11:00+09:00</dcterms:issued>
  <dcterms:modified>2026-10-08T11:00+09:00</dcterms:modified>
 </item>
 <item rdf:about="https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000002.html">
  <title>ルーターの別の脆弱性</title>
  <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000002.html</link>
  <sec:identifier>JVNDB-2026-000002</sec:identifier>
  <sec:references source="CVE" id="CVE-2026-0002">https://www.cve.org/</sec:references>
  <sec:references source="JVN" id="JVNVU#00000001">https://jvn.jp/vu/JVNVU00000001/</sec:references>
  <sec:cpe version="2.2" vendor="Example" product="Router A">cpe:/h:example:a</sec:cpe>
  <sec:cvss version="3.0" score="8.8" type="Base" severity="High" vector="CVSS:3.0/AV:N"/>
  <dcterms:issued>2026-10-08T11:00+09:00</dcterms:issued>
  <dcterms:modified>2026-10-08T11:00+09:00</dcterms:modified>
 </item>
 <item rdf:about="https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000003.html">
  <title>CVSS なし</title>
  <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000003.html</link>
  <sec:identifier>JVNDB-2026-000003</sec:identifier>
  <dcterms:issued>2026-10-08T11:00+09:00</dcterms:issued>
 </item>
</rdf:RDF>
""".encode()


# --- 実データ（fixtures）でのパース ------------------------------------------


def test_parse_jvn_fixture():
    items = fetch.parse_jvn(JVN_XML)
    assert len(items) == 20
    mt = next(i for i in items if i["id"] == "JVN#91153973")
    assert mt["source"] == "jvn"
    assert mt["title"] == "Movable Typeにおける複数の脆弱性"
    assert mt["url"] == "https://jvn.jp/jp/JVN91153973/"
    assert mt["published"] == "2026-10-07T14:00:00+09:00"
    assert mt["cves"] == []
    assert mt["cvss"] is None


def test_parse_ipedia_fixture():
    items = fetch.parse_ipedia(IPEDIA_XML)
    assert len(items) == 500
    chrome = next(i for i in items if i["id"] == "JVNDB-2026-037242")
    assert chrome["cves"] == ["CVE-2026-106302"]
    assert chrome["cvss"] == {"version": "3.0", "score": 5.4, "severity": "Medium"}
    assert chrome["products"] == [{"vendor": "Google", "product": "Google Chrome"}]
    # 秒なしの日時も正規化される
    assert chrome["published"] == "2026-10-08T19:59:00+09:00"


def test_ipedia_summary_has_no_html():
    items = fetch.parse_ipedia(IPEDIA_XML)
    cisa = next(i for i in items if i["id"] == "JVNDB-2026-036917")
    assert "<" not in cisa["summary"]
    assert "\r" not in cisa["summary"]
    assert len(cisa["summary"]) <= fetch.SUMMARY_MAX_CHARS + 1


def test_enrich_matches_fixture():
    result = fetch.build(JVN_XML, IPEDIA_XML, days=7, min_cvss=None, now=NOW)
    item = next(i for i in result["items"] if i["id"] == "JVNVU#94062711")
    assert item["related"] == ["JVNDB-2026-036917"]
    assert item["products"] == [{"vendor": "（複数のベンダ）", "product": "（複数の製品）"}]
    # 照合先に CVSS がないので null のまま
    assert item["cvss"] is None


# --- 小さな XML での個別ケース -----------------------------------------------


def test_cvss_prefers_v3_over_higher_v2():
    items = fetch.parse_ipedia(SMALL_IPEDIA)
    assert items[0]["cvss"] == {"version": "3.0", "score": 6.1, "severity": "Medium"}
    assert items[2]["cvss"] is None


def test_references_split_into_cves_and_jvn():
    item = fetch.parse_ipedia(SMALL_IPEDIA)[0]
    assert item["cves"] == ["CVE-2026-0001"]  # NVD の重複や CWE は入らない
    assert item["related"] == ["JVNVU#00000001"]


def test_clean_summary_strips_tags():
    item = fetch.parse_ipedia(SMALL_IPEDIA)[0]
    assert item["summary"] == "一行目 二行目"


def test_clean_summary_truncates():
    assert fetch.clean_summary("あ" * 500) == "あ" * fetch.SUMMARY_MAX_CHARS + "…"


def test_build_merges_multiple_ipedia_entries():
    result = fetch.build(SMALL_JVN, SMALL_IPEDIA, days=7, min_cvss=None, now=NOW)
    jvn = [i for i in result["items"] if i["source"] == "jvn"]
    assert [i["id"] for i in jvn] == ["JVNVU#00000001"]  # 重複と古い項目が消える
    router = jvn[0]
    assert router["title"] == "Example Router"
    assert router["cves"] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert router["cvss"] == {"version": "3.0", "score": 8.8, "severity": "High"}
    assert router["products"] == [{"vendor": "Example", "product": "Router A"}]
    assert router["related"] == ["JVNDB-2026-000001", "JVNDB-2026-000002"]


def test_build_without_ipedia():
    result = fetch.build(SMALL_JVN, None, days=7, min_cvss=None, now=NOW)
    assert result["counts"] == {"jvn": 1, "ipedia": 0}
    assert result["items"][0]["cvss"] is None


@pytest.mark.parametrize(("min_cvss", "expected"), [(None, 3), (6.0, 2), (8.0, 1), (9.0, 0)])
def test_min_cvss_filters_ipedia_only(min_cvss, expected):
    result = fetch.build(SMALL_JVN, SMALL_IPEDIA, days=7, min_cvss=min_cvss, now=NOW)
    assert result["counts"] == {"jvn": 1, "ipedia": expected}


def test_days_window():
    assert fetch.build(SMALL_JVN, None, days=7, min_cvss=None, now=NOW)["counts"]["jvn"] == 1
    assert fetch.build(SMALL_JVN, None, days=90, min_cvss=None, now=NOW)["counts"]["jvn"] == 2


# --- CLI ---------------------------------------------------------------------


def test_main_from_file(tmp_path, capsys):
    out = tmp_path / "items.json"
    code = fetch.main(
        ["--from-file", str(FIXTURES / "jvn.rdf"), str(FIXTURES / "jvndb_new.rdf"), "--out", str(out), "--list"]
    )
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["counts"]["jvn"] > 0
    assert set(data["items"][0]) == {
        "source",
        "id",
        "title",
        "summary",
        "url",
        "published",
        "modified",
        "cves",
        "cvss",
        "products",
        "related",
    }
    assert "JVN#91153973\t" in capsys.readouterr().out

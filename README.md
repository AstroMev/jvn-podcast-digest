# jvn-podcast-digest

JVN（Japan Vulnerability Notes）の最新の脆弱性情報から、**町のお店・事務所・NPO など非エンジニア向けの「今週のセキュリティニュース」原稿**を作る Claude Code スキルです。
できた原稿を NotebookLM の Audio Overview に入れると、ポッドキャストのように耳で聞けます。

- API キー不要（JVN の公開 RSS だけを使います）
- Python は標準ライブラリのみ
- サンプル原稿：[examples/SECURITY_DIGEST_sample.md](examples/SECURITY_DIGEST_sample.md)

## 何ができるか

```
[1] scripts/fetch.py   JVN の RSS（新着/更新）と JVN iPedia の RSS を取得
                       → 照合して CVE 番号・深刻度を付け、data/items.json に出力
[2] SKILL.md（Claude） 小規模事業者に関係する 3〜5 件を選び、JVN の詳細ページで
                       影響と対策を確認して、音声向けの原稿を書く
                       → output/SECURITY_DIGEST_YYYY-MM-DD.md
[3] あなた             NotebookLM に原稿を入れて音声化
```

選ぶ話題の例：WordPress や Movable Type などの CMS、Wi-Fi ルーター、複合機、ブラウザ、一般向けスマホアプリ。
産業制御系（ICS）、開発者向けライブラリ、大企業向け製品は除外します。

原稿は、専門用語を言い換え、「何の製品か → 何が起きうるか → 何をすればよいか」の順で書きます。攻撃手法の詳細は書かず、一次情報にないことは推測しません。

## 導入方法

前提：[Claude Code](https://claude.com/claude-code) と [uv](https://docs.astral.sh/uv/)（または Python 3.11 以上）

個人のスキルとして入れる場合：

```bash
git clone https://github.com/AstroMev/jvn-podcast-digest.git ~/.claude/skills/jvn-podcast-digest
```

特定のプロジェクトだけで使う場合は、そのプロジェクトの `.claude/skills/jvn-podcast-digest` に clone してください。

## 使い方

Claude Code を起動し、次のように頼みます。

```
今週の脆弱性ニュースを作って
```

「セキュリティダイジェストを作って」「JVN をポッドキャストにして」などでも起動します。
カレントディレクトリに `data/items.json`（取得データ）と `output/SECURITY_DIGEST_YYYY-MM-DD.md`（原稿）ができます。

### fetch.py だけを使う

```bash
uv run scripts/fetch.py                        # 直近7日分を data/items.json に出力
uv run scripts/fetch.py --days 14 --list       # 直近14日分。1項目1行の一覧も表示
uv run scripts/fetch.py --min-cvss 7.0         # iPedia 側を CVSS 7.0 以上に絞る
uv run scripts/fetch.py --from-file tests/fixtures/jvn.rdf tests/fixtures/jvndb_new.rdf  # オフライン
```

| オプション | 説明 |
| --- | --- |
| `--days N` | 公開日または更新日が直近 N 日の項目だけを残す（デフォルト 7） |
| `--min-cvss X` | iPedia 側を CVSS スコアで足切りする（デフォルトなし） |
| `--out PATH` | 出力先（デフォルト `data/items.json`） |
| `--list` | 1項目1行の一覧を標準出力に出す |
| `--from-file JVN IPEDIA` | 保存済みの XML を読む。期間は XML 内の最新日時が基準 |
| `--save-raw DIR` | 取得した XML を保存する（fixtures の作成用） |

出力 JSON の 1 件の形：

```json
{
  "source": "jvn",
  "id": "JVNVU#94062711",
  "title": "...",
  "summary": "...",
  "url": "https://jvn.jp/vu/JVNVU94062711/",
  "published": "2026-10-07T09:00:00+09:00",
  "modified": "2026-10-07T09:00:00+09:00",
  "cves": ["CVE-..."],
  "cvss": {"version": "3.0", "score": 8.8, "severity": "High"},
  "products": [{"vendor": "...", "product": "..."}],
  "related": ["JVNDB-2026-036917"]
}
```

JVN 本体の RSS には CVE 番号と CVSS が入っていないため、iPedia の `sec:references[@source='JVN']` と JVN の `dc:identifier` を突き合わせて補っています。照合できない項目は `cvss` が `null` です（実際には照合できる件数は多くありません）。

## NotebookLM への渡し方

1. [NotebookLM](https://notebooklm.google.com/) で新しいノートブックを作る
2. 「ソースを追加」から `output/SECURITY_DIGEST_YYYY-MM-DD.md` をアップロードする（またはテキストを貼り付ける）
3. 「音声解説（Audio Overview）」の「カスタマイズ」に、たとえば次のように入れて生成する
   > 専門知識のない小規模事業者向けに、やさしい日本語で。各話題で「何をすればよいか」をはっきり伝えてください。
4. できた音声を聞いて、気になる点があれば原稿を直して作り直す

## 開発

```bash
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

テストは `tests/fixtures/` に保存した実際の RSS（2026年10月9日取得）を使います。

## 注意

- RSS の内容は配信時点のものです。原稿でも、最新情報は JVN またはベンダーのサイトで確認するよう促しています
- 原稿は AI が書いたものです。公開・配信する前に、出典と照らし合わせて確認してください
- JVN の詳細ページを読むときは、1秒以上の間隔をあけます

## ライセンス

MIT

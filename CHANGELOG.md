# Changelog

このプロジェクトの変更履歴。日付は W3C 形式、版番号は [Semantic Versioning](https://semver.org/lang/ja/) に従う。

## [1.1.0] - 2026-11-08

### Added
- `--json` フラグ: stdout へ機械可読 JSON 1行のみを出力（funnel・装飾テキスト・ログ一切なし）。
  - `--verifier module:function` 時: `{"verifier": "<spec>", "rows": [...]}`
  - `--demo`（既定）時: verifier ごとの 2 要素配列 `[{verifier: reference_vulnerable, rows}, {verifier: reference_fixed, rows}]`
  - 終了コード規約は不変（全行 PASS=0 / FAIL あり=1 / verifier 解決失敗=2）
- `tests/test_webhook_check.py` に `--json` の出力形状・純 JSON 性・終了コードを検証するテスト 6 件を追加

### Provenance
本機能は agent-work-harness のコントラクト実行により得られた証拠付きマージ候補（contract `webhook-json-output-r2`、receipt `receipt-lease-f3ae83d6635b44e58a545d207f437b3d`、独立レビュー PASS、外部副作用ゼロ）。

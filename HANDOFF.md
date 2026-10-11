# HANDOFF

更新：2026-10-11 · by Claude · HEAD `a544313`
<!-- 規則見 AGENTS.md「Handoff」。上限 150 行；過期內容移到 docs/archive/HANDOFF-YYYY-MM.md。 -->

## ▶ 下一步（只放一件，必須帶 #Issue）
#75 [P0] 修正 production scan 路徑永遠傳 `canonical_disposition='NOT_AVAILABLE'`，導致 CI evidence 永遠到不了 TRIGGERED。依據：唯一 P0 標記；PR #89 已涵蓋最新 invariant 缺口 #84/#85/#86，#75 尚無 PR，main 上 `reviewer/scan.py:143` 仍是寫死值。修法應從 canonical RI engine 取得 disposition，不得在 reviewer 內自建判定邏輯。

## 進行中
- PR #89（Refs #84、#85、#86）publish 前重算 receipt_id、驗證 vendored RIE wheel sha256、WebMCP 擋非 loopback Host/外來 Origin/非 JSON：mergeable=clean，test、e5-live-smoke 與 Nexus Core issue run/completion 最新一輪皆綠（Core issue 綁 #84）。等 owner 審查合併；合併後跑 `nexus-certify issue-check` 再關閉。

## 待確認（沒有 Issue 號）
- 無

## 卡住 / 注意
- #78 [P2] prompt 經 OpenCLI argv 傳遞、prompt 目錄權限未設；#79 [P2] receipt 依 identity 覆寫、`main` 寫死。皆未開工。
- 舊 PR 長期停滯：#32–#39（f4 系列 draft，最後活動 2026-09-20）、#50（hybrid replication capture observer，2026-10-01）。需 owner 決定關閉或重啟，勿當成進行中。
- #51 為 `[HYBRID_CANARY]` 研究探針（no implementation）；`NEXUS-HYBRID-REPLICATION-*` 留言屬 RESEARCH_OBSERVATION_ONLY。
- 語意審查上限為 `PRE_REVIEW_ONLY`；任何修補不得讓 reviewer 取得 approval/merge 權。

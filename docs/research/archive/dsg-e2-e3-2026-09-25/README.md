# DSG-E2 / DSG-E3 Research Archive — 2026-09-25

Status: **research lineage closed**
Final outcome: `EVIDENCE_INSUFFICIENT`
Stop reason: `REPEATED_HARNESS_SEMANTIC_LEAKAGE`
Successor policy: `NO_AUTOMATIC_SUCCESSOR`

This archive preserves the exact DSG-E2/DSG-E3 research lineage from local Candidate
`2a9e5e1ed357a7e8e45d047f0f200ed725e4026f`
(tree `80a824d4d1e191f370fa8f0a58ee1077a91afff5`).

The tarball preserves original repository-relative paths. It intentionally keeps the
prototype/failure lineage outside active Python/test discovery on current main.

## Authority boundary

- Research evidence only.
- No production security policy or runtime enforcement.
- No merge/release/deploy authority.
- Earlier false-green reports and harness iterations are retained as historical evidence.
- The authoritative closeout is `docs/research/dsg_e3/DSG_E3_RESEARCH_CLOSEOUT.md` inside the tarball.

## Integrity

`MANIFEST.json` records source path, byte size, and SHA-256 for every archived file.
Excluded: `__pycache__`, `.pyc`, analyzer downloads, databases, caches, and temporary experiment trees.

## Bounded result

Supported:
- built-in analyzers provided narrow specialist value;
- RV1 had bounded positive runtime-observation evidence;
- RV2 had mixed evidence.

Not proven:
- reusable static-query generalization across the studied families;
- cross-family runtime-invariant generalization;
- trustworthy zero false-positive rate across families;
- production viability or security-policy authority.

Any future runtime-invariant research must use a new lineage, fresh unseen corpus, and an
observation contract frozen before viewing results.

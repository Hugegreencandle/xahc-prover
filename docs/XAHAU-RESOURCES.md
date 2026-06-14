# Xahau Development Resources (curated)

Companion to [XAHAU-DEV-REFERENCE.md](./XAHAU-DEV-REFERENCE.md). Web-scoured **2026-06-14** —
the highest-signal repos, tools, libraries, standards, and learning material for building on
Xahau, each tagged with *why it matters for the trifecta* (xahc · xahau-mcp · xahc-prover).

## Official / canonical
| Resource | URL | Why |
|---|---|---|
| Xahau Docs (live) | https://xahau.network/docs | source of truth; mirrored by our DEV-REFERENCE |
| Docs source repo | https://github.com/Xahau/Xahau-Docs | raw markdown, diffable for "what changed" |
| `xahaud` (node) | https://github.com/Xahau/xahaud | ground truth for transactor + hook VM behaviour; cite in `// verified vs …` comments |
| All Xahau org repos | https://github.com/orgs/Xahau/repositories | xahaud, xahau.js, hooks-rs, xrpl-hooks-ide, … |
| Amendments | https://xahau.network/docs/features/amendments | re-check before claiming a feature exists |

## Hook authoring — canonical headers & toolchains
| Resource | URL | Why |
|---|---|---|
| **hook-macros / hookapi.h** | https://github.com/XRPLF/hook-macros | the authoritative C macros, **sfcodes, keylet codes, field-id scheme** — cross-check xahc headers + prover field IDs against this |
| **hooks-rs** | https://github.com/Xahau/hooks-rs | Rust hook SDK; reference for host-fn signatures + the float/XFL flag maps the prover hard-codes |
| Hook Cleaner | (in xahaud / hooks-toolkit) | strips illegal exports — xahc `clean` reimplements this; compare outputs |
| Compiling Hooks | https://xahau.network/docs/hooks/concepts/compiling-hooks | only `hook`/`cbak` exports; guard reposition rules |

## Examples — real hooks to test the prover/sim against
| Resource | URL | Why |
|---|---|---|
| **XahauHooks101** (Handy4ndy) | https://github.com/Handy4ndy/XahauHooks101 | broad example set: state, emit, params — feed straight into `xahc prove` / xahau-mcp sim as a corpus |
| Xspence Hooks 101 | https://xspence.co.uk/hooks101.html | hands-on guided examples + explanations |
| timestamp-hook example | https://github.com/Ekiserrepe/timestamp-hook-xahau-example | small, well-commented learning hook |
| Hooks Builder (live IDE) | https://hooks-builder.xrpl.org | write/compile/deploy on testnet in-browser; quick A/B vs our local sim |

## Tooling / SDK
| Resource | URL | Why |
|---|---|---|
| Hooks Toolkit | https://hooks-toolkit.com | TS library for compiling, setting, and testing hooks |
| hooks-cli (`@xahau/hooks-cli`) | https://github.com/Transia-RnD/hooks-toolkit-ts-cli | `hooks-cli init` scaffolding — compare against xahc `new` |
| xrpl-hooks-ide | https://github.com/Xahau/xrpl-hooks-ide | the Builder's source (Next.js) — how the official IDE compiles/deploys |

## JavaScript / TypeScript libraries (xahau-mcp, signing, deploy)
| Resource | URL | Why |
|---|---|---|
| **`@transia/xrpl`** | https://www.npmjs.com/package/@transia/xrpl | Xahau-aware xrpl.js fork (hooks fields, Remit, URIToken) |
| **xahau.js** | https://github.com/Xahau (xahau.js) | official JS/TS API for Xahau |
| xrpl-accountlib | (XRPL-Labs) | **signs SetHook + Xahau txns** (used in our testnet validation script: fetch `server_definitions` → `XrplDefinitions` → `sign`) |
| xrpl-client | (XRPL-Labs) | thin resilient WS client to `wss://xahau.network` / `wss://xahau-test.net` |

## Standards (XLS)
| Resource | URL | Why |
|---|---|---|
| XRPL-Standards repo | https://github.com/XRPLF/XRPL-Standards | all XLS specs + discussions |
| **XLS-0101 Smart Contracts** | https://xls.xrpl.org/xls/XLS-0101-smart-contracts.html | the formal smart-contract design — context for where Hooks sit vs the broader XRPL SC roadmap |
| XLS-55 (Remit) | XRPL-Standards/discussions/156 | spec behind the Remit tx |
| XLS-11d (Retiring Amendments) | XRPL-Standards/discussions/19 | amendment lifecycle |
| XLS index (rendered) | https://xls.xrpl.org | browsable standards |

## Learning / talks
| Resource | URL | Why |
|---|---|---|
| Denis Angell — JS Hooks tutorial (XRPL Labs) | https://www.youtube.com/watch?v=uX7bR2VZAp8 | hands-on hook dev from a core contributor |
| XRPL Commons training | https://www.xrpl-commons.org | structured XRPL/Xahau dev training |
| Hooks concept videos | (linked from xahau.network/docs) | state, guards, emit walkthroughs |

## Infrastructure / endpoints
| Thing | Value |
|---|---|
| Mainnet WS / NetworkID | `wss://xahau.network` · **21337** |
| Testnet WS / NetworkID | `wss://xahau-test.net` · **21338** |
| Testnet faucet | `POST https://xahau-test.net/accounts` (rate-limited ~60s) |
| `server_definitions` RPC | field/type/tx-type codes for binary codec + signing |
| Data API | https://data.xahau.network/docs |
| Explorers | xahauexplorer.com · xahscan.com |

## Evernode (if we extend into hosted DApps)
| Resource | URL |
|---|---|
| Evernode docs | https://docs.evernode.org |
| HotPocket SDK / hpdevkit | docs.evernode.org → SDK |

## Security / auditing
Xahau-specific security writeups are still sparse (the network is young). The durable
guidance lives in two places: the **return-codes + guard semantics** in our DEV-REFERENCE
(`GUARD_VIOLATION`, reserve/state limits, `NOT_AUTHORIZED` foreign-state), and **xahc-prover
itself** — the invariants we prove (spend-limit, dst-allowlist, guard-termination,
state-monotonicity, no-double-spend, balance-conservation) ARE the Xahau hook security
checklist, made executable. Treat each new bug class we find as a candidate new invariant.

---
*Maintenance: re-scour when a new Xahau release ships or a major tool lands. The fast-moving
entries are the JS libs and the Builder/toolkit; the headers (hook-macros, hooks-rs) and XLS
specs change slowly.*

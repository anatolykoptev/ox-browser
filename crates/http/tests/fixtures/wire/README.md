# Branded Google Chrome wire captures

Request headers and TLS/HTTP/2 summaries recorded from real, headed, stable
Google Chrome. They are the ground truth for the header layer that the headless
`reference_chrome_*.json` files cannot provide: a headless build advertises a
different brand list and User-Agent, so those references exclude both.

| file | browser | use |
|---|---|---|
| `google_chrome_156_nav.json` | Google Chrome 156.0.8078.80, stable, branded, macOS arm64, first connection of a top-level navigation | oracle for `user-agent`, `sec-ch-ua*`, `accept*`, `sec-fetch-*`, `priority` and header order (`tests/wire_capture_oracle_test.rs`) |
| `google_chrome_156_fetch.json` | same Chrome, page `fetch()`, a later connection | information only: a fetch header set, and its TLS part carries session-resumption extensions |

## Provenance

Both files were captured by the go-stealth project on 2026-11-04 (browser
156.0.8078.80) and imported unchanged from go-stealth v1.29.0,
`testdata/wire/`, which is Apache-2.0 (see `THIRD_PARTY_NOTICES.md`). Each
file's own `provenance` object records browser, exact version, build,
platform, headless flag, capture time, endpoint and mode; the client IP and TCP
fields of the raw echo response are not kept. The custom header names in the
fetch capture were replaced by `x-custom-N` by the capture tool, positions
kept.

## What this does and does not cover

- Covered: header values and order for a Chrome 156 navigation.
- Not covered: TLS and HTTP/2. ox-browser's ClientHello currently differs from
  this capture (it does not offer signature algorithms 0x0904-0x0906, so
  `ja4_r` and `peetprint_hash` differ), which is why no built-in profile
  presents itself as Chrome 156 yet. The live oracle
  (`tests/fingerprint_oracle_test.rs`) is the check for TLS and HTTP/2.
- No branded capture exists for Chrome 148, the active profile. Its
  `sec-ch-ua` is derived from the major (see `profile_hints::sec_ch_ua`) and
  its header order is the Chrome-for-Testing order recorded in
  `reference_chrome_148.json`.

To refresh or add a capture, record a headed branded Chrome against the echo
endpoint, keep the `provenance` object, and add the file here.

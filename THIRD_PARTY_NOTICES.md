# Third-party notices

ox-browser is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`, see [LICENSE](LICENSE)). The AGPL-3.0 applies because part of
the source is ported from, or informed by, a work that is itself AGPL-3.0.

## webclaw

- Upstream: <https://github.com/0xMassi/webclaw>
- Licence: `AGPL-3.0-only` since 2026-04-01 (upstream commit `84b2e609`, v0.3.4,
  "license change to AGPL-3.0"). Earlier releases (v0.1.0 to v0.3.3) were MIT,
  `Copyright (c) 2026 0xMassi`. The current upstream `LICENSE` is the unmodified
  FSF text and carries no separate copyright line; the repository owner is
  `0xMassi`.
- When ox-browser took the code: 2026-07-27 and 2026-07-28 (commits `467a25a`,
  `5df29ba`, `fcba98e`), almost four months after the AGPL switch. The repository
  history holds no earlier port, so the code is treated as taken from the AGPL
  revision.

### Ported files

Ported code, adapted to ox-browser's types (`ReadOutput`, `dom_query`, `wreq`).
These are derivative works and are distributed here under the AGPL-3.0.

| ox-browser file | Upstream path |
|---|---|
| `crates/http/src/llm/mod.rs` | `crates/webclaw-core/src/llm/mod.rs` |
| `crates/http/src/llm/body.rs` | `crates/webclaw-core/src/llm/body.rs` |
| `crates/http/src/llm/cleanup.rs` | `crates/webclaw-core/src/llm/cleanup.rs` |
| `crates/http/src/llm/images.rs` | `crates/webclaw-core/src/llm/images.rs` |
| `crates/http/src/llm/links.rs` | `crates/webclaw-core/src/llm/links.rs` |
| `crates/http/src/llm/metadata.rs` | `crates/webclaw-core/src/llm/metadata.rs` |
| `crates/http/src/llm/noise_text.rs` | text-level subset of `crates/webclaw-core/src/noise.rs` |
| `crates/http/src/tls.rs` | `crates/webclaw-fetch/src/tls.rs` |

### Derived or informed files

Rewritten for `dom_query` rather than copied, but written with the upstream
implementation as the reference. Treated as derived works.

| ox-browser file | Upstream path |
|---|---|
| `crates/http/src/noise.rs` | `crates/webclaw-core/src/noise.rs` |
| `crates/http/src/data_island.rs` | `crates/webclaw-core/src/data_island.rs` |
| `crates/http/src/js_eval.rs` | `crates/webclaw-core/src/js_eval.rs` |

### Prior art, not derived

`crates/http/src/body_cap.rs` and `crates/http/src/config.rs` cite webclaw's
response-size cap as a reference value only. No code was taken.

### Original MIT notice

The upstream files above first existed under webclaw's MIT licence. Its notice is
kept here for the portions that originate from that period:

```
MIT License

Copyright (c) 2026 0xMassi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Earlier releases

Releases up to and including v0.8.21 were published under the MIT licence and
remain available under it. The relicensing applies from the next release.

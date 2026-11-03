# xtid browser vectors

The animation key is not computed by X's server: X's own script runs a CSS
animation in the user's browser and prints what the browser reports. So the
oracle for the animation key is a real browser, and `vectors.json` holds its
answers for 1000 verification keys. The test `xtid_browser_test` holds
`ClientTransaction::new` to them exactly, with no allowance.

## Files

- `live_page.html` - a public, cookie-less page reduced to the verification meta
  tag and the four loading-animation SVGs.
- `live_ondemand.js` - the `ondemand.s` script X shipped, unmodified.
- `vectors.json` - `provenance` (browser, tool versions, time, SHA-256 of the
  page, the script, the runner and the key list, class counts) and `keys`, a list
  of `[verification key (base64), animation key]`.

`browser_inputs_match_their_provenance` fails if the page or the script changed
since the vectors were recorded, so the vectors cannot drift from their inputs.

## Where they come from

Recorded with headless Chromium 148 (playwright-core 1.60) on macOS arm64. The
harness (a small Node script, not part of this crate) serves `live_page.html` from
a local HTTP server with the verification meta tag replaced by each key, runs
`live_ondemand.js` unmodified in the page, intercepts its `crypto.subtle.digest`
call to read the string it hashes
(`<path>!<method>!<time>obfiowerehiring<animation key>`), and records the text
after the keyword. The browser is started with
`--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"`, so nothing leaves the
machine.

The keys include the hard cases by construction: 269 where a colour channel
rounds above 255, 184 below 0, 100 where plain bisection of the easing curve
changes the key, 499 plain.

## Regenerate

When X ships a new `ondemand.s`, re-record the page, the script and the vectors
together with a harness of that shape (Node 20+, a Chromium headless shell), copy
the three files here, and run `cargo test -p ox-twitter xtid`.

## What this does not establish

Only Chromium on arm64 macOS is recorded. Firefox and Safari run the same script
but with different engines (easing solver, colour and matrix serialisation); X
accepts the Chromium value. The vectors cover one page and one script version.

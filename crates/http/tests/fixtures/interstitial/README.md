# Interstitial and quality fixtures

Responses used by `tests/interstitial_fixtures_test.rs`. Format: a `HTTP <status>` line, header
lines, a blank line, the body.

- Captured on 2026-11-14 from public pages with a plain HTTP client. Hostnames of the captured
  sites are replaced by `example.test`; cookie values, session ids, incident and challenge tokens
  and IP addresses are replaced by `REDACTED` / `0.0.0.0`. Large pages are cut at 160 000 bytes.
- `notfound_*_as_200`: the real body of a not-found page with the status rewritten to 200, to
  model a soft 404 (the real response was a 404).
- `imperva_*`: SYNTHETIC. No reachable page produced one; they follow the documented shape of the
  vendor's stub page (an `incident ID` line plus a resource iframe).
- `ok_*`: pages that must NOT be classified as an interstitial or a bad-quality page.
- `ok_bank_home`, `ok_usps`, `ok_walmart`, `ok_vendor_own_site`, `ok_profile_with_signin_chrome`
  are TRIMMED to about 24 KB: the head plus the opening of the body (scripts, styles and
  presentation attributes removed for the profile and the retailer page; for the vendor's own
  site, the head plus its first 14 text blocks). That is the minimum that still has enough text to
  be an ordinary page, the vendor tag or cookies, and the sign-in chrome. They stay above the
  16 KB stub limit on purpose.
- Akamai reference ids in the denial pages are replaced by `REDACTED`.
- `empty_video_shell`: a few third-party config key names containing two common words were masked (`scr_p`, `byp_ss`).

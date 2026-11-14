# Negative quality fixtures

SYNTHETIC short pages (English, Russian, Spanish, French) written for this repo. Each is a real-style page whose
title or body brushes a marker phrase of the content-quality verdict ("sign in", "access denied", "just a moment",
"before you continue", ...) but is ordinary content. `tests/interstitial_fixtures_test.rs` requires every one to come out
`ok`. The catalogue pages are deliberately tiny (no article paragraph) so that only a word-boundary match keeps them
unlabelled; `en_marker_in_body_only` has a neutral title and the phrases only in the body.

//! Holds the animation key to a real browser. testdata/browser/README.md says
//! where the page, the script and the browser answers come from.
use sha2::{Digest, Sha256};

use crate::xtid::ClientTransaction;

const PAGE: &str = include_str!("../testdata/browser/live_page.html");
const SCRIPT: &str = include_str!("../testdata/browser/live_ondemand.js");
const VECTORS: &str = include_str!("../testdata/browser/vectors.json");

fn sha(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).expect("vectors.json parses")
}

#[test]
fn browser_inputs_match_their_provenance() {
    let v = vectors();
    let p = &v["provenance"];
    assert!(p["browser"].as_str().unwrap().starts_with("Chrom"));
    assert_eq!(
        p["pageSha256"].as_str().unwrap(),
        sha(PAGE),
        "live_page.html changed"
    );
    assert_eq!(
        p["scriptSha256"].as_str().unwrap(),
        sha(SCRIPT),
        "live_ondemand.js changed"
    );
    assert_eq!(v["keys"].as_array().unwrap().len(), 1000);
}

/// The page with its verification key replaced, as the recorded browser run did.
fn page_with_key(key: &str) -> String {
    let marker = "name=\"twitter-site-verification\" content=\"";
    let start = PAGE.find(marker).expect("verification meta tag") + marker.len();
    let end = start + PAGE[start..].find('"').unwrap();
    format!("{}{}{}", &PAGE[..start], key, &PAGE[end..])
}

#[test]
fn animation_key_matches_the_browser_on_every_vector() {
    let v = vectors();
    let mut bad = Vec::new();
    let mut total = 0;
    for (i, kv) in v["keys"].as_array().unwrap().iter().enumerate() {
        total += 1;
        let (key, want) = (kv[0].as_str().unwrap(), kv[1].as_str().unwrap());
        match ClientTransaction::new(&page_with_key(key), SCRIPT) {
            Ok(ct) if ct.animation_key() == want => {}
            Ok(ct) => bad.push(format!("#{i} want {want} got {}", ct.animation_key())),
            Err(e) => bad.push(format!("#{i} error {e}")),
        }
    }
    assert!(
        bad.is_empty(),
        "{} of {total} keys differ, first: {:#?}",
        bad.len(),
        &bad[..bad.len().min(8)]
    );
}

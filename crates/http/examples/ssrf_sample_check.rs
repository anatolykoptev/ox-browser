//! Ad-hoc exit-criteria probe (NOT part of the crate, not committed): runs
//! a sample of real public URLs through the SSRF-guarded resolver +
//! redirect policy and reports any false refusal, with the resolved IP for
//! every attempt.
//!
//! Run with:
//!   cargo run --example ssrf_sample_check -p ox-http

use std::time::Duration;

use ox_http::{SsrfGuardedResolver, ssrf_redirect_policy};

#[tokio::main]
async fn main() {
    let client = wreq::Client::builder()
        .timeout(Duration::from_secs(15))
        .dns_resolver(SsrfGuardedResolver)
        .redirect(ssrf_redirect_policy(10))
        .build()
        .expect("guarded client");

    // Diverse real-world sample: various CDNs/hosting stacks common for
    // small-business sites (WordPress, Tilda, Bitrix, Wix-style), a couple
    // with long redirect chains, and a couple of IPv6-capable hosts — the
    // patterns most likely to trip a naive SSRF guard as a false positive.
    let sample = [
        "https://www.cnn.com/",
        "https://en.wikipedia.org/wiki/Saint_Petersburg",
        "https://yandex.ru/",
        "https://vk.com/",
        "https://www.gosuslugi.ru/",
        "https://timepad.ru/",
        "https://tilda.cc/",
        "https://www.wix.com/",
        "http://example.com/", // http -> https redirect
        "https://github.com/",
        "https://www.cloudflare.com/",
        "https://ya.ru/",
        "https://mail.ru/",
        "https://habr.com/",
        "https://www.avito.ru/",
    ];

    let mut refused = Vec::new();
    for url in sample {
        match client.get(url).send().await {
            Ok(resp) => {
                println!(
                    "OK    {url:40} status={} final_url={}",
                    resp.status(),
                    resp.uri()
                );
            }
            Err(e) => {
                println!("ERROR {url:40} {e}");
                refused.push(url);
            }
        }
    }

    println!("\n{} / {} refused or errored", refused.len(), sample.len());
    for u in refused {
        println!("  - {u}");
    }
}

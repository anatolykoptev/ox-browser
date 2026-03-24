# Twitter Site Handler — Design Spec

## Goal

Add Twitter/X content extraction to ox-browser's read pipeline with multi-provider fallback: FxTwitter API (primary, free) → Twitter GraphQL (fallback, ported from go-twitter).

## Supported URLs

- **Tweets:** `twitter.com/user/status/{id}`, `x.com/user/status/{id}`, `mobile.twitter.com/...`
- **Profiles:** `twitter.com/{screen_name}`, `x.com/{screen_name}`

## Output Format

### Tweet
```
@screen_name · 2026-03-24

Tweet text here...

♥ 1,234  🔁 567  💬 89  👁 12,345
```

### Profile
```
@screen_name · Display Name
Bio text here...

Followers: 12,345 · Following: 678 · Tweets: 9,012

--- Recent tweets ---

[♥ 42] Tweet text 1...
[♥ 10] Tweet text 2...
```

## Architecture

### New crate: `crates/twitter`

| File | Responsibility | ~Lines |
|------|---------------|--------|
| `types.rs` | `Tweet`, `UserProfile` structs | ~50 |
| `url.rs` | Parse twitter/x.com URLs → `TweetRef` or `ProfileRef` | ~60 |
| `fxtwitter.rs` | FxTwitter API client — `fetch_tweet`, `fetch_profile` | ~80 |
| `graphql.rs` | Twitter GraphQL — endpoints, features, bearer token | ~130 |
| `request.rs` | Build GraphQL requests — headers, variables, URL encoding | ~70 |
| `parser.rs` | Parse GraphQL timeline JSON → `Tweet`/`UserProfile` | ~100 |
| `client.rs` | Fallback orchestrator — tries FxTwitter → GraphQL | ~60 |
| `format.rs` | Format `Tweet`/`UserProfile` → text output | ~50 |

### New file: `crates/http/src/site_twitter.rs`

Handler in read pipeline (like `site_reddit.rs`). Detects twitter.com/x.com URLs, delegates to `crates/twitter` client, returns `ReadOutput` with `method=twitter`.

### Modify: `crates/http/src/read_pipeline.rs`

Add `try_twitter` call after `try_reddit_json`, before generic `http.get()`.

## HTTP Client Strategy

Both FxTwitter and GraphQL use a **standalone wreq client** (not the shared `HttpClient`), similar to how the original reddit handler was designed. Reasons:

- GraphQL needs custom headers (`Authorization: Bearer`, `x-twitter-active-user`) that the middleware chain would interfere with
- FxTwitter is a simple GET that doesn't need CF bypass, retry, or rate limiting
- Both go through residential proxy via `RESIDENTIAL_PROXY_URL` env var (same as Reddit)
- Each creates a short-lived `wreq::Client` with `emulation(Chrome136)` and `cookie_store(true)`

## Fallback Chain

```
1. FxTwitter API (verified working for both tweets and profiles)
   Tweets:   GET https://api.fxtwitter.com/i/status/{id}
   Profiles: GET https://api.fxtwitter.com/{screen_name}
   → JSON response, no auth needed
   → 5s timeout
   → If 200 + valid JSON → parse → return
   → If error/timeout/404 → try next

2. Twitter GraphQL (ported from go-twitter)
   Tweets:   GET https://x.com/i/api/graphql/{op_id}/TweetDetail?variables=...&features=...
   Profiles: GET https://x.com/i/api/graphql/{op_id}/UserByScreenName?variables=...&features=...
             + GET .../UserTweets?variables=...&features=... (for recent tweets)
   Headers: Authorization: Bearer {public_token}, etc.
   → Via wreq + Chrome TLS emulation + residential proxy
   → 10s timeout
   → Parse timeline JSON → extract tweet/user data
   → If success → return
   → If error → return error

3. No headless/Byparr fallback (Twitter blocks headless browsers)
```

## Twitter GraphQL Details (from go-twitter)

### Bearer Token

**Decoded form** (for `Authorization` header):
```
AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA
```

Note: go-twitter's `endpoints.go` stores the URL-encoded form (`%3D` for `=`). The Rust implementation must use the decoded form above in the `Authorization: Bearer` header.

Public, hardcoded in Twitter's web app JS. No user auth needed for read-only.

### Endpoints
| Operation | GraphQL ID | Use |
|-----------|-----------|-----|
| `TweetDetail` | `zXaXQgfyR4GxE21uwYQSyA` | Single tweet by ID |
| `UserByScreenName` | `sLVLhk0bGj3MVFEKTdax1w` | User profile by @handle |
| `UserTweets` | `HuTx74BxAnezK1gWvYY7zg` | Recent tweets for user |

### Required Headers
```
authorization: Bearer {token}
x-twitter-active-user: yes
x-twitter-client-language: en
content-type: application/json
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
```

No `x-csrf-token` or `ct0` cookie needed for anonymous read-only requests. If Twitter starts requiring them, the GraphQL fallback may need guest token activation (future work).

### Feature Flags
33 boolean flags from `gqlFeatures()` in go-twitter's `endpoints.go:54-89`. Must be included in query params as URL-encoded JSON. Port the exact map.

### Request Format
```
GET {base}/{op_id}/{op_name}?variables={url_encoded_json}&features={url_encoded_json}
```

### Response Parsing — TweetDetail

TweetDetail returns a **timeline** wrapper, NOT a flat `data.tweetResult`. The actual path is:
```
data
  .threaded_conversation_with_injections_v2  (or similar timeline key)
    .instructions[]
      .entries[]
        .content
          .itemContent  (may be null — skip if so)
            .__typename == "TimelineTweet"
            .tweet_results.result
              .rest_id → tweet ID
              .legacy → {full_text, favorite_count, retweet_count, quote_count, reply_count, ...}
              .legacy.created_at → "Mon Jan 02 15:04:05 +0000 2006" format
              .views.count → view count (string)
              .core.user_results.result
                .legacy → {screen_name, name, ...}
```

Port `extractTweetsFromTimeline()` and `parseTweetResult()` from go-twitter's `parsers.go:227-325`. The focal tweet is the first `TimelineTweet` entry matching the requested ID.

### Response Parsing — UserByScreenName

```
data.user.result
  .rest_id → user ID
  .legacy → {screen_name, name, description, followers_count, friends_count, statuses_count, ...}
  .is_blue_verified → bool
```

Port `parseUserResult()` from go-twitter's `parsers.go:258-287`.

### Response Parsing — UserTweets

Same timeline wrapper as TweetDetail:
```
data.user.result.timeline_v2.timeline  (fallback: .timeline.timeline)
  .instructions[].entries[].content.itemContent.tweet_results.result
```

Port `parseTweetTimeline()` from go-twitter's `parsers.go:75-98`.

## Types

```rust
pub struct Tweet {
    pub id: String,
    pub text: String,
    pub author_id: String,
    pub author_name: String,
    pub author_screen_name: String,
    pub created_at: String,
    pub likes: u64,
    pub retweets: u64,
    pub quotes: u64,
    pub replies: u64,
    pub views: u64,
}

pub struct UserProfile {
    pub id: String,
    pub name: String,
    pub screen_name: String,
    pub bio: String,
    pub followers: u64,
    pub following: u64,
    pub tweet_count: u64,
    pub verified: bool,
    pub recent_tweets: Vec<Tweet>,
}
```

Intentionally omitted vs go-twitter's `TwitterUser`: `is_blue_verified` (folded into `verified`), `has_avatar`, `has_bio`, `listed_count`, `created_at` — not needed for read-only content display.

## Proxy Routing

Both FxTwitter and GraphQL requests go through residential proxy (`RESIDENTIAL_PROXY_URL` env var) to avoid datacenter IP blocks. This is set on the wreq `Client::builder().proxy()` — same pattern as the Reddit handler.

## Rate Limiting

Twitter anonymous GraphQL is limited to ~50 requests/15 min. The existing `DomainLimiter` (wired in this session) handles this automatically — add a `*.twitter.com` / `*.x.com` rule in the ratelimit config defaults:

```toml
[[ratelimit.rules]]
domain = "*.x.com"
requests_per_window = 40
window_secs = 900
min_delay_ms = 1000
random_delay_ms = 500
```

FxTwitter has its own limits but is external — if it 429s, we fall back to GraphQL.

## Dependencies

- `wreq` + `wreq_util` — HTTP with Chrome TLS (already in workspace)
- `serde`, `serde_json` — JSON parsing
- `url` — URL parsing
- `tracing` — logging

No new external dependencies.

## Error Handling

- FxTwitter timeout (5s) → try GraphQL
- FxTwitter non-200 or invalid JSON → try GraphQL
- GraphQL 403/429 → return error (rate limited, no further fallback)
- Invalid tweet ID / deleted tweet → return None from handler
- Suspended/private user → return None
- Network errors → return None, let read pipeline return error output

## Testing

- URL parsing: twitter.com, x.com, mobile.twitter.com, with/without trailing slash, edge cases (non-tweet paths like /settings)
- FxTwitter tweet response parsing (mock JSON — capture real response and save as fixture)
- FxTwitter profile response parsing (mock JSON)
- GraphQL TweetDetail response parsing (construct fixture from go-twitter's parser structure)
- GraphQL UserByScreenName response parsing
- GraphQL UserTweets timeline parsing
- Fallback chain: FxTwitter fail → GraphQL success
- Fallback chain: both fail → None
- Format output: tweet text, profile text
- Edge cases: deleted tweet (404), suspended user, very long tweet (>280 chars, truncation)

Test fixtures: capture real FxTwitter responses via `curl https://api.fxtwitter.com/i/status/{id}` and `curl https://api.fxtwitter.com/{screen_name}`. For GraphQL, construct from go-twitter's parser inline structs.

## Not In Scope

- Authentication (account pool, ct0 rotation, CAPTCHA)
- Tweet creation, search, followers/following lists
- Media download (images/video from tweets)
- Guest token activation (future work if bearer stops working)
- Thread/conversation expansion (only focal tweet extracted)

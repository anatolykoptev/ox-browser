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
| `types.rs` | `Tweet`, `UserProfile` structs | ~40 |
| `url.rs` | Parse twitter/x.com URLs → `TweetRef` or `ProfileRef` | ~60 |
| `fxtwitter.rs` | FxTwitter API client — `fetch_tweet`, `fetch_profile` | ~80 |
| `graphql.rs` | Twitter GraphQL — endpoints, features, bearer token, request builder | ~100 |
| `parser.rs` | Parse GraphQL JSON → `Tweet`/`UserProfile` | ~80 |
| `client.rs` | Fallback orchestrator — tries FxTwitter → GraphQL | ~60 |
| `format.rs` | Format `Tweet`/`UserProfile` → text output | ~50 |

### Modify: `crates/http/src/site_twitter.rs`

Handler in read pipeline (like `site_reddit.rs`). Detects twitter.com/x.com URLs, delegates to `crates/twitter` client, returns `ReadOutput` with `method=twitter`.

### Modify: `crates/http/src/read_pipeline.rs`

Add `try_twitter` call after `try_reddit_json`, before generic `http.get()`.

## Fallback Chain

```
1. FxTwitter API
   GET https://api.fxtwitter.com/i/status/{id}
   GET https://api.fxtwitter.com/{screen_name}
   → JSON response, no auth needed
   → If 200 + valid JSON → parse → return
   → If error/timeout/404 → try next

2. Twitter GraphQL (ported from go-twitter)
   GET https://x.com/i/api/graphql/{op_id}/TweetDetail?variables=...
   GET https://x.com/i/api/graphql/{op_id}/UserByScreenName?variables=...
   Headers: Authorization: Bearer {public_token}, x-csrf-token, etc.
   → Via wreq + Chrome TLS emulation + residential proxy
   → Parse timeline JSON → extract tweet/user data
   → If success → return
   → If error → return error

3. No headless/Byparr fallback (Twitter blocks headless browsers)
```

## Twitter GraphQL Details (from go-twitter)

### Bearer Token
```
AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA
```
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
```

No `x-csrf-token` or `ct0` cookie needed for anonymous read-only requests with this bearer token. If Twitter starts requiring them, the GraphQL fallback may need guest token activation (future work).

### Feature Flags
33 boolean flags from `gqlFeatures()` in go-twitter. Must be included in query params as JSON.

### Request Format
```
GET {base}/{op_id}/{op_name}?variables={json}&features={json}
```

Variables for TweetDetail:
```json
{
  "focalTweetId": "{tweet_id}",
  "with_rux_injections": false,
  "rankingMode": "Relevance",
  "includePromotedContent": true,
  "withCommunity": true,
  "withQuickPromoteEligibilityTweetFields": true,
  "withBirdwatchNotes": true,
  "withVoice": true
}
```

### Response Parsing
Response is deeply nested JSON. Key path for tweet:
```
data.tweetResult.result.legacy → {full_text, favorite_count, retweet_count, ...}
data.tweetResult.result.core.user_results.result.legacy → {screen_name, name, ...}
```

Port `parseTweetResult()` and `extractTweetsFromTimeline()` from go-twitter's `parsers.go`.

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
    pub recent_tweets: Vec<Tweet>,
}
```

## Dependencies

- `wreq` + `wreq_util` — HTTP with Chrome TLS (already in workspace)
- `serde`, `serde_json` — JSON parsing
- `url` — URL parsing
- `tracing` — logging

No new external dependencies.

## Error Handling

- FxTwitter timeout (5s) → try GraphQL
- FxTwitter non-200 → try GraphQL
- GraphQL 403/429 → return error (rate limited, no further fallback)
- Invalid tweet ID / deleted tweet → return None from handler
- Network errors → return None, let middleware chain handle original URL

## Testing

- URL parsing: twitter.com, x.com, mobile.twitter.com, with/without trailing slash
- FxTwitter response parsing (mock JSON)
- GraphQL response parsing (mock JSON from go-twitter test data)
- Fallback chain: FxTwitter fail → GraphQL success
- Format output: tweet text, profile text
- Edge cases: deleted tweet, suspended user, private account

## Not In Scope

- Authentication (account pool, ct0 rotation, CAPTCHA)
- Tweet creation, search, followers/following lists
- Media download (images/video from tweets)
- Guest token activation (future work if bearer stops working)

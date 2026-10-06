# Registry verification, 2026-08-24

`crates/core/registry/providers.json` was written from memory and had never been checked
against the world it describes. This is the record of checking it. Every row was
produced by an actual HTTP request, not by recollection; where a request could
not settle the question, the row says UNVERIFIED and says why.

Reproduce with `scripts/verify-registry.py`, which does both sweeps and prints
its own table. No real credential is read, sent or stored: the liveness sweep
probes with a constant string that is not a key for anything.

## What was checked

**URLs.** Every `url`, the page a human is sent to in order to create the key,
was fetched with redirects followed and a browser User-Agent. The final URL is
recorded as well as the status, because the failure mode that matters is not a
404: it is a dead deep link that the provider quietly 302s onto its marketing
homepage, which returns a perfectly green 200 and helps nobody.

A console that 302s to a login page is **not** a broken link. That is the
console working; the redirect carries the destination in its `return_to`, and
the user lands on the right page after signing in. Those rows read "login wall"
and were left alone. Likewise a 401/403 from a bot-protected marketing edge.

**Checks.** Every `check` was called with an obviously invalid credential using
the exact auth style the registry declares. `apply_auth` in the script mirrors
`crates/core/src/validate.rs` line for line, so what was probed is what the
binary sends. The bar is that an invalid key must produce the provider's
documented auth-failure status. A 404 means the endpoint is wrong; a 400 about
an unknown header means the auth style is wrong; a 200 means the endpoint never
required auth and the probe proves nothing.

**Patterns.** Every `pattern` was compared against the provider's current
documented key format. The asymmetry here is deliberate: a pattern that is too
loose costs a round trip, while a pattern that is too strict refuses the paste at
the one moment the human has the key on their clipboard. Patterns were therefore
only ever widened, and never narrowed without a documented source.

## Result

| | count |
| --- | --- |
| providers | 79 |
| URLs already correct | 61 |
| URLs fixed | 18 |
| URLs broken and unfixed | 0 |
| checks present before | 28 |
| checks confirmed correct | 22 |
| checks fixed | 5 |
| checks removed | 1 |
| patterns present before | 47 |
| patterns confirmed correct | 35 |
| patterns loosened | 10 |
| patterns removed | 1 |
| patterns UNVERIFIED, left as-is | 1 |

Two rows are marked UNVERIFIED on the URL side and neither is a broken link:
`EXA_API_KEY` sits behind a Vercel bot challenge that answers 429 to any
scripted fetch, and both Clerk entries answer 404 to an unauthenticated request
on *every* path under `dashboard.clerk.com` except `/sign-in`. In both cases the
URL is the one the provider's own documentation hands out, so HTTP status is
simply not evidence here. This is worth remembering before anyone wires a link
checker into CI: for auth-gated single-page consoles, a 200 is evidence of an
unauthenticated page, which is usually the wrong page.

### The five checks that could not reject anything

`liveness()` only ever sees the HTTP status, and treated everything other than
401/403 as "accept". Four providers use the right endpoint and the right auth
style but do not spell auth failure as 401: Google answers 400 INVALID_ARGUMENT
for a bad API key, xAI answers 400 invalid-argument, Resend answers 400
validation_error, and Brave answers 422 SUBSCRIPTION_TOKEN_INVALID. All four
were confirmed with a correctly-shaped-but-invalid key as well as a nonsense
one, so the status is about the credential and not about the request shape. They
now carry `reject_status`, a new optional `Check` field for exactly this.

Sending an `AIza` key to Google as a bearer token does produce a 401, but only
because Google then reads it as an OAuth token, so a *valid* key would be rejected
too. That is worse than no check, so the auth style was left as the API-key
style it should be.

The fifth is Slack, and Slack cannot be fixed this way. Its Web API answers HTTP
200 to everything, including `{"ok":false,"error":"invalid_auth"}`; `auth.test`,
`users.identity` and `apps.connections.open` were all probed and all did. Since
`liveness()` never sees a body, the probe was decoration. **`SLACK_BOT_TOKEN`'s
check has been removed** rather than left in place looking like a guarantee. If
body-level rejection is ever wanted, it needs a `reject_body` field and a change
in `validate.rs`; that is a deliberate future decision, not something to imply
by leaving a dead probe in the file.

### The pattern that mattered most

`GEMINI_API_KEY` and `GOOGLE_API_KEY` required `^AIza`. Google AI Studio now
issues *auth keys* by default, which are `AQ.`-prefixed, and Google's docs state
the Gemini API "will reject requests from Standard keys" from September 2026.
So `^AIza` is not merely rejecting new keys. It is on track to reject every key
that still works. The prefix itself is not printed in Google's documentation,
only confirmed by Google staff on Google's own forum, so the pattern now accepts
both rather than switching outright. `GOOGLE_MAPS_API_KEY` keeps `^AIza`: Maps
Platform is a separate key system and is unaffected.

Second worst: `GITHUB_TOKEN` rejected `ghs_`, which is exactly what GitHub
Actions' built-in `GITHUB_TOKEN` is, a GitHub App
installation access token in GitHub's own docs, so the pattern fired on the single most common value
that variable ever holds.

### Left alone, on purpose

`GOOGLE_CLIENT_SECRET` keeps `^GOCSPX-` and is marked UNVERIFIED. No Google
document states the client-secret format; the prefix appears only in a codelab
literal, and OAuth clients created before 2021 have unprefixed 24-character
secrets that this pattern would reject. It is not widened because there is no
documented alternative to widen *to*, and guessing a format is exactly the
failure this exercise exists to undo.

`AIRTABLE_API_KEY` went the other way and lost its pattern entirely. Airtable
documents its tokens as opaque variable-length strings whose format may change
without that counting as a breaking change, and its OAuth access tokens have no
documented shape at all, so `^pat` was asserting something Airtable explicitly
declines to promise.

A handful of patterns are marked OK on the strength of official *examples*
rather than official prose. They are Groq, DeepSeek, Perplexity and Firecrawl. The prefix
is what the provider prints in its own quickstart, but no document guarantees
it. They are correct today and are noted here so the next person knows the
evidence is one notch weaker than a spec.

## Every provider

Statuses in the **url** and **check** columns are what the sweep actually
received on 2026-08-24, after the fixes in this branch. "login wall" means the
deep link 302s to sign-in, which is correct behaviour. "declared" means the
provider's auth-failure status is not 401/403 and the check now says so via
`reject_status`. "none" in the check column means the provider has no liveness
probe, which is most of them.

| name | url | check | pattern verdict | action taken | source |
| --- | --- | --- | --- | --- | --- |
| `OPENAI_API_KEY` | OK (403, login or bot wall) | OK (401) | OK `^sk-`, sk-proj-/sk-svcacct-/sk-admin- all keep it | none | [docs](https://developers.openai.com/api/docs/guides/admin-apis) |
| `ANTHROPIC_API_KEY` | OK (200) | OK (401) | OK `^sk-ant-`, api03/admin01/api01 all keep it | url -> platform.claude.com/settings/keys | [docs](https://platform.claude.com/docs/en/manage-claude/admin-api-keys) |
| `GEMINI_API_KEY` | OK (200, login wall) | OK (400, declared) | LOOSENED `^AIza` -> `^(AIza\|AQ\.)`, AI Studio now issues AQ. auth keys | pattern loosened; check declares reject_status 400 | [docs](https://ai.google.dev/gemini-api/docs/api-key) |
| `GOOGLE_API_KEY` | OK (200, login wall) | OK (400, declared) | LOOSENED, same as GEMINI_API_KEY | pattern loosened; check declares reject_status 400 | [docs](https://ai.google.dev/gemini-api/docs/api-key) |
| `GROQ_API_KEY` | OK (200) | OK (401) | OK `^gsk_` (docs show the prefix in examples only) | none | [docs](https://console.groq.com/docs/production-readiness/security-onboarding) |
| `MISTRAL_API_KEY` | OK (307, login wall) | OK (401) | no pattern | none |  |
| `OPENROUTER_API_KEY` | OK (200, login wall) | OK (401) | OK `^sk-or-`, keys are sk-or-v1- | none | [docs](https://openrouter.ai/docs/features/provisioning-api-keys) |
| `XAI_API_KEY` | OK (403, login or bot wall) | OK (400, declared) | OK `^xai-` | check declares reject_status 400 (xAI answers 400, not 401) | [docs](https://docs.x.ai/developers/rest-api-reference/management/auth) |
| `DEEPSEEK_API_KEY` | OK (202) | OK (401) | OK `^sk-` (examples only) | none | [docs](https://api-docs.deepseek.com/) |
| `TOGETHER_API_KEY` | OK (200, login wall) | OK (401) | no pattern | none |  |
| `FIREWORKS_API_KEY` | OK (200) | none | LOOSENED `^fw_` -> `^(fw_\|fpk_)`, Fire Pass keys are fpk_ | url 404 -> app.fireworks.ai/settings/users/api-keys | [docs](https://docs.fireworks.ai/getting-started/quickstart) |
| `PERPLEXITY_API_KEY` | OK (403, login or bot wall) | none | OK `^pplx-` (examples only) | none | [docs](https://docs.perplexity.ai/docs/admin/api-key-management) |
| `COHERE_API_KEY` | OK (200, login wall) | OK (401) | no pattern | none |  |
| `HF_TOKEN` | OK (200, login wall) | OK (401) | OK `^hf_`, hf_jwt_/hf_oauth_ keep it | none | [docs](https://huggingface.co/docs/hub/trusted-publishers) |
| `REPLICATE_API_TOKEN` | OK (200, login wall) | OK (401) | OK `^r8_`, docs state 40 chars always starting r8_ | none | [docs](https://replicate.com/docs/topics/security/api-tokens) |
| `FAL_KEY` | OK (200, login wall) | none | no pattern | none |  |
| `ELEVENLABS_API_KEY` | OK (200) | OK (401) | no pattern | url -> /app/developers/api-keys |  |
| `DEEPGRAM_API_KEY` | OK (200) | OK (401) | no pattern | none |  |
| `TAVUS_API_KEY` | OK (403, login or bot wall) | none | no pattern | none |  |
| `TAVILY_API_KEY` | OK (200) | none | OK `^tvly-`, tvly-dev-/prod keep it | url -> app.tavily.com/home | [docs](https://docs.tavily.com/documentation/quickstart) |
| `EXA_API_KEY` | UNVERIFIED (429 bot challenge) | none | no pattern | UNVERIFIED url: 429 Vercel bot challenge, unfetchable; docs confirm the URL | [docs](https://exa.ai/docs/reference/getting-started) |
| `SERPER_API_KEY` | OK (200) | none | no pattern | url 404 -> serper.dev/api-keys (plural) | UNVERIFIED: serper.dev has no docs site; route confirmed live |
| `FIRECRAWL_API_KEY` | OK (200, login wall) | none | OK `^fc-` (examples only) | none | [docs](https://docs.firecrawl.dev/api-reference/introduction) |
| `BRAVE_API_KEY` | OK (200, login wall) | OK (422, declared) | no pattern | check declares reject_status 422 (Brave answers 422 SUBSCRIPTION_TOKEN_INVALID) | [docs](https://api-dashboard.search.brave.com/app/documentation) |
| `STRIPE_SECRET_KEY` | OK (200, login wall) | OK (401) | LOOSENED `^(sk\|rk)_(test\|live)_` -> `^(sk\|rk)_`, org keys are sk_org_ with no infix | pattern + sensitive_pattern widened to cover sk_org_ | [docs](https://docs.stripe.com/keys/organization-api-keys) |
| `STRIPE_PUBLISHABLE_KEY` | OK (200, login wall) | none | OK `^pk_(test\|live)_`, organizations have no publishable keys | none | [docs](https://docs.stripe.com/keys) |
| `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` | OK (200, login wall) | none | OK, same as STRIPE_PUBLISHABLE_KEY | none | [docs](https://docs.stripe.com/keys) |
| `STRIPE_WEBHOOK_SECRET` | OK (200, login wall) | none | OK `^whsec_`, also v2 event destinations | none | [docs](https://docs.stripe.com/webhooks) |
| `RESEND_API_KEY` | OK (200, login wall) | OK (400, declared) | OK `^re_` | check declares reject_status 400 (Resend answers 400) | [docs](https://resend.com/docs/api-reference/introduction) |
| `SENDGRID_API_KEY` | OK (200) | OK (401) | OK `^SG\.` | none | [docs](https://www.twilio.com/docs/sendgrid/api-reference/api-keys/create-api-keys) |
| `POSTMARK_SERVER_TOKEN` | OK (202, login wall) | OK (401) | no pattern | none |  |
| `TWILIO_ACCOUNT_SID` | OK (200) | none | OK `^AC`, docs give ^AC[0-9a-fA-F]{32}$ | none | [docs](https://www.twilio.com/docs/iam/api/account) |
| `TWILIO_AUTH_TOKEN` | OK (200) | none | no pattern | none |  |
| `SUPABASE_URL` | OK (200) | none | OK project-URL shape | url -> Data API overview (Settings -> API was split) | [docs](https://supabase.com/docs/guides/api) |
| `NEXT_PUBLIC_SUPABASE_URL` | OK (200) | none | OK project-URL shape | url -> Data API overview | [docs](https://supabase.com/docs/guides/api) |
| `SUPABASE_ANON_KEY` | OK (200) | none | OK `^(eyJ\|sb_publishable_)`, legacy JWT valid to end of 2026 | url -> Settings -> API Keys | [docs](https://supabase.com/docs/guides/api/api-keys) |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | OK (200) | none | OK, same as SUPABASE_ANON_KEY | url -> Settings -> API Keys | [docs](https://supabase.com/docs/guides/api/api-keys) |
| `SUPABASE_SERVICE_ROLE_KEY` | OK (200) | none | OK `^(eyJ\|sb_secret_)` | url -> Settings -> API Keys | [docs](https://supabase.com/docs/guides/api/api-keys) |
| `DATABASE_URL` | OK (200, login wall) | none | OK connection-scheme list | url neon.tech (now marketing) -> console.neon.tech/app/projects | [docs](https://neon.com/faqs/find-database-connection-string) |
| `NEON_API_KEY` | OK (200, login wall) | OK (401) | no pattern | none |  |
| `UPSTASH_REDIS_REST_URL` | OK (200) | none | OK `^https://` | none |  |
| `UPSTASH_REDIS_REST_TOKEN` | OK (200) | none | no pattern | none |  |
| `VERCEL_TOKEN` | OK (200, login wall) | OK (403) | no pattern | none |  |
| `GITHUB_TOKEN` | OK (200, login wall) | OK (401) | LOOSENED -> `^(ghp_\|gho_\|ghu_\|ghs_\|ghr_\|github_pat_)`, Actions' own GITHUB_TOKEN is ghs_ | pattern loosened | [docs](https://docs.github.com/en/actions/concepts/security/github_token) |
| `CLOUDFLARE_API_TOKEN` | OK (403, login or bot wall) | OK (401) | no pattern | none |  |
| `AWS_ACCESS_KEY_ID` | OK (200, login wall) | none | OK `^(AKIA\|ASIA)`, ABIA/ACCA are not access key IDs | none | [docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html) |
| `AWS_SECRET_ACCESS_KEY` | OK (200, login wall) | none | no pattern | none |  |
| `CLERK_SECRET_KEY` | OK (404 unauthenticated; docs-canonical) | none | OK `^sk_(test\|live)_` | url -> dashboard.clerk.com/~/api-keys (bare host 404s) | [docs](https://clerk.com/docs/guides/development/machine-auth/api-keys) |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | OK (404 unauthenticated; docs-canonical) | none | OK `^pk_(test\|live)_` | url -> dashboard.clerk.com/~/api-keys | [docs](https://clerk.com/docs/guides/development/clerk-environment-variables) |
| `AUTH_SECRET` | OK (200) | none | no pattern (locally generated) | none |  |
| `NEXTAUTH_SECRET` | OK (200) | none | no pattern (locally generated) | none |  |
| `SESSION_SECRET` | OK (200) | none | no pattern (locally generated) | none |  |
| `JWT_SECRET` | OK (200) | none | no pattern (locally generated) | none |  |
| `ENCRYPTION_KEY` | OK (200) | none | no pattern (locally generated) | none |  |
| `GOOGLE_CLIENT_ID` | OK (200, login wall) | none | OK `\.apps\.googleusercontent\.com$` | none | [docs](https://developers.google.com/identity/protocols/oauth2/web-server) |
| `GOOGLE_CLIENT_SECRET` | OK (200, login wall) | none | UNVERIFIED `^GOCSPX-`, no Google doc states the format; pre-2021 secrets are unprefixed and would be rejected | left as-is; nothing documented to widen to | [docs](https://support.google.com/cloud/answer/15549257) |
| `GITHUB_CLIENT_ID` | OK (200, login wall) | none | no pattern | none |  |
| `GITHUB_CLIENT_SECRET` | OK (200, login wall) | none | no pattern | none |  |
| `MAPBOX_ACCESS_TOKEN` | OK (200) | none | LOOSENED `^(pk\|sk)\.` -> `^(pk\|sk\|tk)\.`, tk is a documented temporary token | url -> console.mapbox.com (account.mapbox.com is legacy) | [docs](https://docs.mapbox.com/api/accounts/tokens/) |
| `NEXT_PUBLIC_MAPBOX_TOKEN` | OK (200) | none | OK `^pk\.`, a public token must be pk | url -> console.mapbox.com | [docs](https://docs.mapbox.com/api/accounts/tokens/) |
| `GOOGLE_MAPS_API_KEY` | OK (200, login wall) | none | OK `^AIza`, Maps Platform keys are not affected by the AI Studio auth-key change | none | [docs](https://developers.google.com/maps/api-security-best-practices) |
| `OPENWEATHER_API_KEY` | OK (200, login wall) | none | no pattern | none |  |
| `PINECONE_API_KEY` | OK (200) | OK (401) | no pattern | none |  |
| `SENTRY_DSN` | OK (200, login wall) | none | LOOSENED `^https://[a-f0-9]+@` -> `^https?://[a-fA-F0-9]+@`, Relay and self-hosted issue http:// DSNs; charset never guaranteed lowercase | url sentry.io (marketing) -> /settings/projects/ | [docs](https://docs.sentry.io/concepts/key-terms/dsn-explainer/) |
| `NEXT_PUBLIC_POSTHOG_KEY` | OK (200, login wall) | none | OK `^phc_` | none | [docs](https://posthog.com/docs/api) |
| `POSTHOG_API_KEY` | OK (200, login wall) | none | LOOSENED `^phx_` -> `^(phx_\|phs_)`, phs_ project secret keys | pattern loosened | [docs](https://posthog.com/docs/api/project-secret-api-keys) |
| `LANGSMITH_API_KEY` | OK (200) | none | OK `^lsv2_`, lsv2_pt_ and lsv2_sk_ | none | [docs](https://docs.smith.langchain.com/administration/concepts) |
| `SLACK_BOT_TOKEN` | OK (200) | none | LOOSENED `^xoxb-` -> `^(xoxe\.)?xoxb-`, rotation-enabled apps get xoxe.xoxb- | CHECK REMOVED: Slack's Web API answers 200 to everything | [docs](https://docs.slack.dev/authentication/using-token-rotation) |
| `DISCORD_BOT_TOKEN` | OK (200) | OK (401) | no pattern | none |  |
| `NOTION_API_KEY` | OK (200) | OK (401) | OK `^(secret_\|ntn_)`, ntn_ since 2024-09-25, secret_ still valid | url -> app.notion.com/developers/connections; steps renamed to connections | [docs](https://developers.notion.com/page/changelog) |
| `LINEAR_API_KEY` | OK (200) | none | LOOSENED `^lin_api_` -> `^lin_(api\|oauth)_`, OAuth tokens use the same header | pattern loosened | [docs](https://linear.app/developers/oauth-2-0-authentication) |
| `AIRTABLE_API_KEY` | OK (403, login or bot wall) | none | REMOVED `^pat`, Airtable documents its tokens as opaque variable-length strings and its OAuth tokens have no documented shape | pattern removed | [docs](https://airtable.com/developers/web/guides/personal-access-tokens) |
| `ALGOLIA_APP_ID` | OK (403, login or bot wall) | none | no pattern | none |  |
| `ALGOLIA_API_KEY` | OK (403, login or bot wall) | none | no pattern | none |  |
| `CLOUDINARY_URL` | OK (200) | none | OK `^cloudinary://` | none | [docs](https://cloudinary.com/documentation/node_integration) |
| `UPLOADTHING_TOKEN` | OK (200, login wall) | none | no pattern | none |  |
| `RAILWAY_TOKEN` | OK (200) | none | no pattern | url railway.app -> railway.com | [docs](https://docs.railway.com/) |
| `FLY_API_TOKEN` | OK (200, login wall) | none | no pattern | none |  |
| `NPM_TOKEN` | OK (403, login or bot wall) | none | OK `^npm_`, classic tokens revoked 2025-11-19 | none | [docs](https://docs.npmjs.com/about-access-tokens) |


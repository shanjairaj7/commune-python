# Common Errors

A reference for errors you might encounter when using commune-mail.

---

## 1. AuthenticationError (401)

**Message:** `Invalid or expired API key`

**Cause:** The `COMMUNE_API_KEY` environment variable is not set, the key has been revoked, or the key was copied incorrectly.

**Fix:**

```python
# Option 1: Set env var before running your script
export COMMUNE_API_KEY="comm_your_key_here"

# Option 2: Pass directly to the client
from commune import CommuneClient
client = CommuneClient(api_key="comm_your_key_here")
```

Get your key from the [Commune dashboard](https://commune.email). API keys start with `comm_` followed by 64 hex characters. The raw key is only shown once at creation — if you've lost it, revoke it and create a new one.

---

## 2. NotFoundError (404)

**Message:** `Inbox not found` / `Thread not found` / `Domain not found`

**Cause:** The resource ID passed doesn't exist in your organization, or it was deleted. Common cause: passing the inbox email address (`support@agents.commune.email`) where the inbox ID (`i_abc123`) is expected.

**Fix:**

```python
from commune import NotFoundError

try:
    inbox = client.inboxes.get("d_abc123", "i_xyz")
except NotFoundError:
    # Re-create or look up the correct inbox
    inboxes = client.inboxes.list()
    inbox = next((i for i in inboxes if i.local_part == "support"), None)
```

Remember: `inbox_id` is the `id` field (e.g. `i_abc123`), not the email address string.

---

## 3. ValidationError (400)

**Message:** `Invalid email address` / `Missing required field: subject` / `text or html is required`

**Cause:** A required parameter is missing, or a value fails server-side validation. Common cases: missing `to` or `subject`, an invalid email address format, an empty body (neither `text` nor `html` provided), or `limit` out of the allowed range.

**Fix:**

```python
from commune import ValidationError

try:
    client.messages.send(
        to="user@example.com",
        subject="Hello",
        text="Hi there",      # must provide text or html
        inbox_id=inbox.id,    # use inbox.id, not inbox.address
    )
except ValidationError as e:
    print(f"Bad request: {e.message}")
```

Check the [API_REFERENCE.md](API_REFERENCE.md) for required vs. optional fields on each method.

---

## 4. RateLimitError (429)

**Message:** `Rate limit exceeded. Retry after {n} seconds.`

**Cause:** Your organization has exceeded the per-hour or per-day send limit, or a burst of requests triggered the sliding-window rate limiter.

**Fix:**

```python
import time
from commune import RateLimitError

for recipient in recipients:
    try:
        client.messages.send(to=recipient, subject="...", text="...", inbox_id=inbox.id)
    except RateLimitError as e:
        retry_after = int(e.headers.get("Retry-After", 60))
        time.sleep(retry_after)
        client.messages.send(to=recipient, subject="...", text="...", inbox_id=inbox.id)
```

Check the `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers on successful responses to monitor usage. Upgrade your plan if you consistently hit limits.

---

## 5. PermissionDeniedError (403)

**Message:** `API key does not have the required scope: messages:write`

**Cause:** Your API key was created with restricted permission scopes and the operation you're attempting requires a scope that wasn't granted. For example, a read-only key trying to send email.

**Fix:**

```python
from commune import PermissionDeniedError

try:
    client.messages.send(...)
except PermissionDeniedError as e:
    print(f"Permission denied: {e.message}")
    # Go to the dashboard, create a new key with the required scopes:
    # messages:write, inboxes:write, etc.
```

From the [Commune dashboard](https://commune.email), create a new API key with the scopes your agent needs. Available scopes: `domains:read`, `domains:write`, `inboxes:read`, `inboxes:write`, `threads:read`, `messages:read`, `messages:write`, `attachments:read`, `attachments:write`.

---

## 6. Webhook signature verification fails

**Message:** `WebhookVerificationError: Invalid signature` or `WebhookVerificationError: Timestamp too old`

**Cause:** Either the wrong webhook secret is being used, the raw request body was modified before verification (e.g. parsed by a JSON middleware and re-serialized), or the timestamp is more than 5 minutes old (replay attack protection).

**Fix:**

```python
from commune import verify_signature, WebhookVerificationError

@app.post("/webhook")
async def handle_email(request: Request):
    # IMPORTANT: read the raw body bytes before any parsing
    body = await request.body()

    try:
        verify_signature(
            payload=body,                                         # raw bytes, not parsed JSON
            signature=request.headers["x-commune-signature"],
            secret=os.environ["COMMUNE_WEBHOOK_SECRET"],         # whsec_... from dashboard
            timestamp=request.headers["x-commune-timestamp"],
        )
    except WebhookVerificationError as e:
        return Response(status_code=401, content=str(e))

    payload = json.loads(body)
    # ... process
```

The webhook secret (`whsec_...`) is separate from the API key (`comm_...`). Find it in the inbox settings on the dashboard. Make sure your framework isn't consuming `request.body()` before your handler runs.

---

## 7. `inbox.address` returns `@agents.commune.email` instead of your custom domain

**Symptom:** After creating an inbox with `domain_id="d_abc123"`, the address still shows `support@agents.commune.email` instead of `support@yourcompany.com`.

**Cause:** Your custom domain hasn't been verified yet. DNS records need to propagate before Commune can accept mail for your domain.

**Fix:**

```python
# Check domain status
domain = client.domains.get("d_abc123")
print(domain.status)  # "not_started", "pending", or "verified"

if domain.status != "verified":
    records = client.domains.records("d_abc123")
    print("Add these DNS records at your registrar:")
    for r in records:
        print(f"  {r['type']}  {r['name']}  →  {r['value']}")
    # After adding records, trigger verification:
    client.domains.verify("d_abc123")
```

DNS propagation typically takes 5–30 minutes. Re-check with `client.domains.get()` after a few minutes. If status stays `"pending"` for over an hour, double-check the records are added correctly with `dig MX yourcompany.com`.

---

## 8. Thread reply doesn't appear as a thread in Gmail or Outlook

**Symptom:** You reply to an inbound email with `messages.send(...)`, but the customer sees it as a new separate email conversation instead of a reply in the same thread.

**Cause:** The `thread_id` parameter was not passed to `messages.send()`. Without it, Commune creates a new message with no relation to the original thread.

**Fix:**

```python
# In your webhook handler, extract thread_id from the payload
payload = json.loads(body)
thread_id = payload["thread_id"]       # always present on inbound messages
sender = payload["from"]

# Pass thread_id when replying
client.messages.send(
    to=sender,
    subject="Re: " + payload["subject"],
    text="Thanks for writing in — here's our response...",
    inbox_id=inbox.id,
    thread_id=thread_id,               # this is what groups it in the email client
)
```

The `thread_id` comes from the webhook payload when an email arrives, or from `threads.list()` if you're processing older emails. It is a required field for any reply — never optional.

---

## 9. `send()` succeeds but email never arrives

**Symptom:** `client.messages.send()` returns without error, but the recipient never receives the email. No bounce notification either.

**Cause:** The recipient's email address is on the suppression list. Hard bounces and spam complaints automatically add addresses to suppression. Sending to a suppressed address is silently dropped to protect your domain reputation.

**Fix:**

```python
# Check the suppression list for your inbox
suppressions = client.delivery.suppressions(inbox_id=inbox.id)
suppressed_addresses = [s["email"] for s in suppressions]

if "user@example.com" in suppressed_addresses:
    print("Address is suppressed — do not send")
    # If suppression was a mistake, remove via dashboard or contact support

# Check delivery events for debug info
events = client.delivery.events(domain_id=domain.id, limit=20)
for event in events:
    print(event["type"], event["recipient"], event.get("reason"))
```

Other causes: the recipient's mail server rejected the message (check `events` for bounce details), or the email was caught by the recipient's spam filter (ensure DKIM/SPF are verified on your domain).

---

## 10. Extraction schema not being applied to inbound emails

**Symptom:** Inbound webhook payloads don't include the `extracted` field, or it's always `null`, even though you set an extraction schema on the inbox.

**Cause:** Either the schema was set on a different `inbox_id` than the one receiving mail, the schema was not enabled after creation, or the `domain_id` / `inbox_id` pair was incorrect when calling `set_extraction_schema`.

**Fix:**

```python
# Verify the schema was set on the correct inbox
inbox = client.inboxes.get(domain_id, inbox_id)
print(inbox)  # check for extraction schema in the response

# Re-apply if needed — make sure domain_id and inbox_id match the receiving inbox
client.inboxes.set_extraction_schema(
    domain_id=domain.id,       # must match the domain the inbox belongs to
    inbox_id=inbox.id,         # must be the inbox that receives the webhook
    name="my_schema",
    schema={
        "type": "object",
        "properties": {
            "intent": {"type": "string"},
            "priority": {"type": "string"},
        },
    },
)
```

After setting the schema, send a test email to the inbox and check the webhook payload. The `extracted` field should appear alongside `content` and `thread_id`.

---

## 11. ClamAV attachment scan fails (self-hosted only)

**Message:** `Attachment scan failed: connection refused` or attachments stuck in processing

**Cause:** This only affects self-hosted Commune deployments. The `CLAMAV_HOST` environment variable is not set, or the ClamAV daemon (`clamd`) is not running at the configured host/port.

**Fix:**

```bash
# Option 1: Start ClamAV daemon (example for Ubuntu/Debian)
sudo apt-get install clamav-daemon
sudo freshclam           # update virus definitions
sudo systemctl start clamav-daemon

# Option 2: Set the env var to point at your clamd instance
export CLAMAV_HOST=127.0.0.1
export CLAMAV_PORT=3310  # default clamd port

# Option 3: Disable ClamAV — fall back to heuristic scanning
# Simply don't set CLAMAV_HOST. Commune automatically falls back to
# heuristic scanning (extension, MIME, magic bytes, VBA macros).
```

For cloud-hosted Commune (commune.email), attachment scanning is always active and does not require any configuration. This error only occurs when running the Commune server yourself.

---

## 12. Async client hangs or never resolves

**Symptom:** An `await` call on the `AsyncCommuneClient` never completes, or the script exits without sending the email.

**Cause:** Either you forgot to `await` an async call (in which case you'd get a coroutine object, not a result), or you used `async with` inside a function that wasn't declared `async`, or `asyncio.run()` was called from within an already-running event loop (common in Jupyter notebooks).

**Fix:**

```python
import asyncio
from commune import AsyncCommuneClient

# Correct: use async with and await every call
async def send_email():
    async with AsyncCommuneClient(api_key="comm_...") as client:
        inbox = await client.inboxes.create(local_part="support")  # don't forget await
        await client.messages.send(
            to="user@example.com",
            subject="Hello",
            text="Hi",
            inbox_id=inbox.id,
        )

asyncio.run(send_email())

# In Jupyter notebooks, use await directly (event loop already running):
# await send_email()
# Or install nest_asyncio: import nest_asyncio; nest_asyncio.apply()
```

If you're inside a FastAPI route handler, the function is already `async` — just `await` the commune calls directly without wrapping in `asyncio.run()`.

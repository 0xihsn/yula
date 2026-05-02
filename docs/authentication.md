# Authentication Guide

YULA AI Scanner supports six authentication methods, configured in the target YAML file
under the `auth:` block.

---

## `none` — No Authentication

```yaml
auth:
  type: none
```

No credentials are sent. Use this for local development servers or public
endpoints that don't require authentication.

---

## `api_key` — API Key as Bearer Token

```yaml
auth:
  type: api_key
  api_key: "${OPENAI_API_KEY}"
```

Sends `Authorization: Bearer <api_key>` header. The standard for OpenAI,
Anthropic, and most LLM providers.

For Anthropic targets, YULA AI Scanner automatically sends the key as `x-api-key`
instead of `Authorization: Bearer`.

---

## `bearer` — Custom Bearer Token

```yaml
auth:
  type: bearer
  token: "${MY_TOKEN}"
```

Sends `Authorization: Bearer <token>`. Identical to `api_key` for HTTP targets.
Use when the credential is called "token" rather than "key".

---

## `basic` — HTTP Basic Authentication

```yaml
auth:
  type: basic
  username: "admin"
  password: "${MY_PASSWORD}"
```

Sends `Authorization: Basic <base64(username:password)>`. Used for internal
services protected by HTTP Basic Auth.

---

## `cookie` — Session Cookie Injection

```yaml
auth:
  type: cookie
  cookies:
    - name: "session"
      value: "${SESSION_TOKEN}"
      domain: "myapp.internal"
      path: "/"
      secure: false
    - name: "csrf_token"
      value: "${CSRF_TOKEN}"
      domain: "myapp.internal"
      path: "/"
      secure: false
```

For API targets: cookies are sent in the `Cookie` HTTP header.
For web targets: cookies are injected directly into the Playwright browser
context before navigating to the target URL.

---

## `form_login` — Browser Form Login (Web Targets Only)

```yaml
auth:
  type: form_login
  login_url: "http://localhost:3000/login"
  username_selector: "#email"
  password_selector: "#password"
  submit_selector: "button[type=submit]"
  username: "${APP_USERNAME}"
  password: "${APP_PASSWORD}"
  post_login_wait_ms: 2000
```

Playwright navigates to `login_url`, fills the username and password fields,
clicks the submit button, and waits `post_login_wait_ms` milliseconds for
the redirect/authentication to complete before proceeding to the target URL.

Use CSS selectors for `username_selector`, `password_selector`, and `submit_selector`.
Right-click the form field in your browser's DevTools to find the correct selector.

---

## Environment Variable Substitution

All credential values support `${ENV_VAR_NAME}` syntax. The variable is resolved
from the environment at startup. If the variable is not set, YULA AI Scanner exits with
a clear error message.

```bash
# Set credentials before running
export OPENAI_API_KEY=sk-...
export SESSION_TOKEN=eyJhb...

python run.py scan --target config/targets/my_target.yaml
```

Or use a `.env` file in the YULA AI Scanner/ directory:

```
# .env
OPENAI_API_KEY=sk-...
SESSION_TOKEN=eyJhb...
```

---

## Credential Security

- **Never hardcode credentials** in YAML files — always use environment variables
- **Never commit `.env` files** to version control — add `.env` to `.gitignore`
- The `.dockerignore` file already excludes `.env` from Docker images
- YULA AI Scanner logs requests at DEBUG level — avoid enabling DEBUG logging in production

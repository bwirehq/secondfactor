# Quickstart

Prerequisites: Git, Go 1.26.10+, Python 3, OpenSSL, and Docker Compose. Use a new checkout. Commands below create **development-only** credentials and never overwrite an existing `secrets/` directory.

```sh
sh scripts/dev-setup.sh
docker compose up --build -d
python3 scripts/smoke.py
```

The API listens at `https://localhost:8443`; the demo application listens at `https://localhost:9443`. `secrets/dev.crt` is the generated development CA. The demo password is in `secrets/demo-password`; read it locally and do not share or commit it. Do not trust this development CA globally.

The script checks a working protected route automatically. For manual use, send JSON with `Origin: https://localhost:9443`, use the development certificate, and maintain a secure cookie jar. Example login using Python avoids putting passwords in process arguments:

```python
import http.cookiejar, json, pathlib, ssl, urllib.request
jar = http.cookiejar.CookieJar()
http = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='secrets/dev.crt')),
    urllib.request.HTTPCookieProcessor(jar))
def call(path, body=None):
    req = urllib.request.Request('https://localhost:9443' + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Origin': 'https://localhost:9443', 'Content-Type': 'application/json'})
    with http.open(req) as response: return json.load(response)
call('/login', {'password': pathlib.Path('secrets/demo-password').read_text().strip()})
setup = call('/mfa/enroll', {})
# Display setup['uri'] locally to the account owner, or enter setup['secret']
# into an authenticator. Do not log it or use an external QR-generation service.
confirmation = call('/mfa/confirm', {'code': input('Authenticator code: ')})
# Safely display confirmation['recovery_codes'] once and save them offline.
call('/protected')
# Wait for the next authenticator code before verification: replay is rejected.
call('/mfa/verify', {'code': input('Next authenticator code: ')})
call('/mfa/regenerate', {})
# Regeneration invalidates proofs. Verify a new code before protected access.
call('/logout', {})
```

## Run without an API container

Start the development database, migrate explicitly, then run the service and example in separate terminals:

```sh
docker compose up -d postgres
go run ./cmd/secondfactor migrate --config config.local.json
go run ./cmd/secondfactor serve --config config.local.json
```

```sh
go work init . ./examples/go-http
go run ./examples/go-http
```

The root library never reads environment variables. The CLI loads a validated operator JSON configuration and secret-file references.

Stop with `docker compose down`. `docker compose down -v` also destroys the development database. Do not delete encryption keys while retaining a database that needs them.

These steps are local development only. Replace mock primary authentication, recoverability policy, certificates, database roles, networking, monitoring, and secrets management before production deployment.

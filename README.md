# hook-receiver

A minimal webhook receiver in pure Python: verifies an HMAC-SHA256 signature
on every POST and appends verified payloads to a JSONL log. Single file,
standard library only - useful for local integration testing of webhooks
without exposing a real endpoint.

## Signature scheme

```
X-Signature: hex( HMAC-SHA256( secret, raw_request_body ) )
```

Requests with a missing, malformed or wrong signature get `403`. The
comparison is constant-time (`hmac.compare_digest`), and the signature is
bound to the exact bytes of the body, so tampering is rejected.

## Usage

```console
$ export HOOK_SECRET='my-shared-secret'
$ hook-receiver --port 8080 --log hooks.jsonl
hook-receiver listening on http://127.0.0.1:8080/hook

# in another terminal:
$ BODY='{"event":"push","n":1}'
$ SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$HOOK_SECRET" -hex | sed 's/^.* //')
$ curl -s -X POST http://127.0.0.1:8080/hook \
      -H "Content-Type: application/json" -H "X-Signature: $SIG" -d "$BODY"
{"ok": true}

$ cat hooks.jsonl
{"ts": "2026-09-28T12:00:00+00:00", "payload": {"event": "push", "n": 1}}

$ python3 hook_receiver.py --test
selftest: failures=0
```

As a module:

```python
from hook_receiver import HookServer
srv = HookServer(port=0, secret="s3cret", log_file="hooks.jsonl")
srv.start_background()
# POST to srv.port with a valid X-Signature
srv.stop()
```

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--port` | 8080 | listen port (`0` picks a free port) |
| `--host` | 127.0.0.1 | bind address |
| `--path` | /hook | accepted POST path |
| `--secret-env` | HOOK_SECRET | env var holding the shared secret |
| `--log` | none | JSONL file for verified payloads |

## Testing

```console
$ python3 hook_receiver.py --test
```

Covers valid/bad/missing signatures, body tampering, wrong path, exact log
contents and request counters.

## License

MIT

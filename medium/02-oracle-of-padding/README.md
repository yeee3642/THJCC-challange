# Oracle of Padding (medium)

Our session tokens are AES-128-CBC, so they are encrypted, so they are secret.
The service will happily tell you whether a token you hand it is well formed —
that is just input validation, it leaks nothing.

```
nc <host> 1337
```

or locally:

```
python3 server.py
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 server.py"   # as a service
```

The service prints `TOKEN <hex>` (IV ‖ ciphertext) on connect, then answers
`OK` / `BAD` for every hex blob you send. Budget: 200000 queries.

Flag format: `THJCC{...}`

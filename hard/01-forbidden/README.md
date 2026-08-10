# Forbidden (hard)

AES-GCM is authenticated encryption: without the key you cannot forge a tag.
Our notice board publishes three signed notices. The nonce lives in the config
file, right next to the key, so it is just as constant — one less thing to get
wrong at runtime.

Send back a ciphertext and a tag that authenticate to the `TARGET` plaintext
under that same nonce and the flag is yours. You get 100 attempts.

```
nc <host> 1339
python3 server.py                                                # local
socat TCP-LISTEN:1339,reuseaddr,fork EXEC:"python3 server.py"    # as a service
```

> Hint: GHASH is a polynomial evaluation in GF(2^128), and the authentication
> key `H` is the point it is evaluated at. Two tags under one nonce give you an
> equation. You will need polynomial arithmetic — and root finding — in that
> field; nothing in the standard library does it for you.

Flag format: `THJCC{...}`

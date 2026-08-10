# Nonce Sense (medium)

Our signing service is secp256k1 ECDSA with SHA-256, the same thing that
secures a trillion dollars of Bitcoin. To keep latency down we generate the
per-session randomness once, when the connection opens, and reuse it. Random
is random.

Connect, collect the two demo signatures, and hand back a valid signature over
the `TARGET` message to get the flag. You do **not** get the private key.

```
nc <host> 1338
python3 server.py                                                # local
socat TCP-LISTEN:1338,reuseaddr,fork EXEC:"python3 server.py"    # as a service
```

Flag format: `THJCC{...}`

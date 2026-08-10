# A Million Messages (hard)

Legacy inventory system. RSA with PKCS#1 v1.5 padding, because that is what the
1998 hardware speaks. Yes, we know about OAEP; no, we cannot change it this
quarter.

The service tells you whether a ciphertext you submit decrypts to something
with well-formed padding. It never tells you the plaintext, and it never
returns any decrypted data, so there is nothing to leak.

```
nc <host> 1340
python3 server.py                                                # local
socat TCP-LISTEN:1340,reuseaddr,fork EXEC:"python3 server.py"    # as a service
```

On connect you get `N`, `E` and `C` (the padded flag). Then every hex blob you
send is answered `OK` / `BAD`. Two million queries — you will need a lot fewer,
but not *that* many fewer.

> Hint: valid padding means the plaintext starts with `0x00 0x02`, i.e. it lies
> in a known narrow interval. Multiplying the ciphertext by `s^e` multiplies the
> plaintext by `s`. Every `OK` intersects the interval with a shifted copy of
> itself, and the interval collapses to a single value.

Flag format: `THJCC{...}`

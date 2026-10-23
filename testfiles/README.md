# Test captures

Two small synthetic IKEv2 captures for trying the dashboard's PCAP upload. Each holds one session of four packets: `IKE_SA_INIT` request and response on UDP 500 (these carry the proposals), then `IKE_AUTH` request and response on UDP 4500 (encrypted, so random bytes).

| File | Negotiated | nist-baseline | cnsa-strict |
| --- | --- | --- | --- |
| `weak_test.pcap` | 3DES-CBC, HMAC-MD5, MODP-1024 | High risk, 40/100: forbidden DH group (`IPSEC-DH-001`), forbidden integrity (`IPSEC-INT-001`), deprecated encryption (`IPSEC-ALG-002`) | High risk, 25/100: `IPSEC-ALG-001`, `IPSEC-DH-001`, `IPSEC-INT-001` |
| `secure_test.pcap` | AES-256-CBC, HMAC-SHA2-384, ECP-384 | Compliant, 100/100 | Compliant, 100/100 |

## Read this before relying on them

- These are generated, not captured from a real VPN. The key exchange values, nonces and ciphertext are random filler. The proposals are real IKEv2 structures, laid out exactly as StrongSwan writes them (the SA payload bytes are identical to the ones in `samples/`), so they exercise parsing and assessment, not cryptography.
- The results above come from running the rule engine on the parameters encoded in the files. They have not been confirmed through `tshark` and the analyzer, which was not installed where the files were made. If your upload shows something different, trust the dashboard and tell us.
- For real traffic see `samples/`, captured between two StrongSwan hosts.

## Use

Upload either file with **Upload capture or JSON** (needs `tshark` on the server), or run `python analyze.py testfiles/weak_test.pcap`.

## Regenerate

```bash
python testfiles/generate_testfiles.py
```

Output is deterministic. Edit `SCENARIOS` in that script to make other cases (the transform ids are the IANA IKEv2 numbers).

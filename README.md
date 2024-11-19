# tlsserial - groks x509 certificates for your pleasure

## Usage

```console
❯ poetry install
❯ poetry run tlsserial
Usage: tlsserial [OPTIONS]

  tlsserial groks X509 certificates for your pleasure

Options:
  --url TEXT   host || host:port || https://host:port/other NOTE: This
               argument is mutually exclusive with arguments: [file].
  --file TEXT  filename containing a PEM certificate NOTE: This argument is
               mutually exclusive with arguments: [url].
  --debug
  --help       Show this message and exit.
```

### from a URL

```console
❯ poetry run tlsserial --url dell.com
issuer                   : [CN] Entrust Certification Authority - L1K [O] Entrust, Inc. [C] US
subject                  : [CN] Dell.com [O] Dell [L] Round Rock [ST] Texas [C] US
subject_alt_name         : Dell.com
not_before               : 2022-08-04T17:45:04+00:00
not_after                : 2023-08-28T17:45:04+00:00 (expires within 30 days!)
public_key_algorithm     : RSAPublicKey (2048 bit)
signature_algorithm      : sha256WithRSAEncryption params(PKCS1v15)
key_usage                : digital_signature, key_encipherment
ext_key_usage            : clientAuth, serverAuth
crls                     : http://crl.entrust.net/level1k.crl
ocsp                     : http://ocsp.entrust.net
ca_issuers               : http://aia.entrust.net/l1k-chain256.cer
serial_number            : 5AF6B00AD82F3B8FACCEF4123D36138C
```

### from a file

```console
❯ poetry run tlsserial --file ~/axiom.crt
issuer                   : [CN] Amazon ECDSA 384 M02 [O] Amazon [C] US
subject                  : [CN] *.axiom-partners.com
subject_alt_name         : *.axiom-partners.com
not_before               : 2023-07-05T00:00:00+00:00
not_after                : 2024-08-02T23:59:59+00:00
public_key_algorithm     : EllipticCurvePublicKey secp384r1 (384 bit)
signature_algorithm      : ecdsa-with-SHA384 params(n/a)
key_usage                : digital_signature
ext_key_usage            : clientAuth, serverAuth
crls                     : http://crl.e3m02.amazontrust.com/e3m02.crl
ocsp                     : http://ocsp.e3m02.amazontrust.com
ca_issuers               : http://crt.e3m02.amazontrust.com/e3m02.cer
serial_number            : 0C9E25D31C5E5ECABC2AB6F10D89C3AF
```


## Development

poetry install
poetry run pre-commit install
poetry run pytest -v

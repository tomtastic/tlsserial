# tlsserial - groks x509 certificates for your pleasure

## Usage

```shell
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

## from a URL

```shell
❯ poetry run tlsserial --url bbc.co.uk
issuer                   : [CN] GlobalSign RSA OV SSL CA 2018 [O] GlobalSign nv-sa [C] BE
ca_issuers               : http://secure.globalsign.com/cacert/gsrsaovsslca2018.crt
subject                  : [CN] www.bbc.com [O] BRITISH BROADCASTING CORPORATION [L] London [ST] London [C] GB
subject_alt_name         : *.bbc.com
subject_alt_name         : *.bbcrussian.com
subject_alt_name         : bbc.co.uk
subject_alt_name         : bbc.com
subject_alt_name         : bbcrussian.com
subject_alt_name         : www.bbc.co.uk
subject_alt_name         : www.bbc.com
not_before               : 2023-03-14T06:16:13+00:00
not_after                : 2024-04-14T06:16:12+00:00
keytype_and_sig          : RSAPublicKey 2048bits (SHA256) (PKCS1v15)
key_usage                : digital_signature, key_encipherment
ext_key_usage            : clientAuth, serverAuth
crls                     : http://crl.globalsign.com/gsrsaovsslca2018.crl
ocsp                     : http://ocsp.globalsign.com/gsrsaovsslca2018
serial_number            : 27A1771A5D445E527D7E70B7
```

## from a file

```shell
❯ poetry run tlsserial --file ~/axiom.crt
issuer                   : [CN] Amazon ECDSA 384 M02 [O] Amazon [C] US
ca_issuers               : http://crt.e3m02.amazontrust.com/e3m02.cer
subject                  : [CN] *.axiom-partners.com
subject_alt_name         : *.axiom-partners.com
not_before               : 2023-07-05T00:00:00+00:00
not_after                : 2024-08-02T23:59:59+00:00
keytype_and_sig          : EllipticCurvePublicKey secp384r1 384bits (SHA384) (n/a)
key_usage                : digital_signature
ext_key_usage            : clientAuth, serverAuth
crls                     : http://crl.e3m02.amazontrust.com/e3m02.crl
ocsp                     : http://ocsp.e3m02.amazontrust.com
serial_number            : 0C9E25D31C5E5ECABC2AB6F10D89C3AF
```

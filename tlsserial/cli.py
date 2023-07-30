#!/usr/bin/env python3
""" grab some things from a TLS cert """
# TODO:
# - Show basic constraints
# - Show SHA256 fingerprint
# - Show the full certificate chain
# - Compare against INTB (and others) cipher suite?
#   - Clarify ciphers in use
#     eg.
#       - peer signing digest
#       - server temp keys
#       - server public keys
#       - TLS cipher?
import logging
import re
import sys
from ssl import OPENSSL_VERSION
import click
from cryptography import x509

import tlsserial.helper
from tlsserial.nice_certificate import NiceCertificate
from tlsserial.color import bold, red, orange, blue


# https://click.palletsprojects.com/en/8.1.x/quickstart/
@click.command()
@click.option(
    "--url",
    cls=tlsserial.helper.MutuallyExclusiveOption,
    mutually_exclusive=["file"],
    help="host || host:port || https://host:port/other"
)
@click.option(
    "--file",
    cls=tlsserial.helper.MutuallyExclusiveOption,
    mutually_exclusive=["url"],
    help="filename containing a PEM certificate"
)
@click.option(
    "--debug",
    is_flag=True,
    type=bool,
    default=False
)
def main(url, file, debug) -> None:
    """tlsserial groks X509 certificates for your pleasure"""
    level = logging.DEBUG
    fmt = "[%(levelname)s] %(asctime)s - %(message)s"
    logging.basicConfig(level=level, format=fmt)

    if url:
        host, port = get_args(url)
        cert = tlsserial.helper.get_cert_from_host(host, port)
        if cert[0] is not None:
            display(host, parse_x509(cert[0]))
        else:
            print(cert[1])
    elif file:
        host = ""
        cert = tlsserial.helper.get_cert_from_file(file)
        if cert[0] is not None:
            display(host, parse_x509(cert[0]))
        else:
            print(cert[1])
    else:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())

    #click.echo(f"Library version : {OPENSSL_VERSION}")


def get_args(argv: str) -> tuple:
    """
    Try to extract a hostname and port from input string
    Returns a tuple of (host, port)
    """
    args_matched = re.search(r"([0-9a-zA-Z\-\.]{6,63})[\ :]?([0-9]{2,5})?", argv)
    if args_matched is not None:
        if args_matched[1] is not None:
            if args_matched[1] is not None:
                if args_matched[2] is not None and args_matched[2].isdigit:
                    # host and specified port
                    return (args_matched[1], args_matched[2])
                # host and default port
                return (args_matched[1], 443)
    print(f"Error parsing the input : {argv}")
    sys.exit(1)


def parse_x509(cert: x509.Certificate) -> NiceCertificate:
    """Parse an ugly X509 object"""
    """Return a NiceCertificate object """

    # We use helper functions where parsing is gnarly
    notBefore, notAfter = tlsserial.helper.get_before_and_after(cert)
    ocsp, ca_issuers = tlsserial.helper.get_ocsp_and_caissuer(cert)

    return NiceCertificate(
        # We use helper functions where parsing is gnarly
        issuer=tlsserial.helper.get_issuer(cert),
        ca_issuers=ca_issuers,
        subject=tlsserial.helper.get_subject(cert),
        sans=tlsserial.helper.get_sans(cert),
        key_usage=tlsserial.helper.get_key_usage(cert),
        ext_key_usage=tlsserial.helper.get_ext_key_usage(cert),
        not_before=notBefore,
        not_after=notAfter,
        crls=tlsserial.helper.get_crls(cert),
        ocsp=ocsp,
        serial_as_int=cert.serial_number,
        version=cert.version,
        key_type=tlsserial.helper.get_key_type(cert),
        key_bits=tlsserial.helper.get_key_bits(cert),
        key_factors=tlsserial.helper.get_key_factors(cert),
        sig_algo=tlsserial.helper.get_sig_algorithm(cert),
        sig_algo_params=tlsserial.helper.get_sig_algorithm_params(cert),
    )


def display(host: str, cert: NiceCertificate) -> None:
    """Print nicely-formatted attributes of a NiceCertificate object"""
    print_items = [
        "issuer",
        "ca_issuers",
        "subject",
        "subject_alt_name",
        "not_before",
        "not_after",
        "keytype_and_sig",
        "key_usage",
        "ext_key_usage",
        "crls",
        "ocsp",
        "serial_number",
    ]

    width = 24
    matched_host = False
    for item in print_items:
        if "issuer" == item:
            print(f"{orange(f'{item:<{width}}')} : {' '.join(cert.issuer)}")
        elif "subject" == item:
            cert.subject = [
                f"{c[:5]}{bold(blue(c[5:]))}" if c.endswith(f" {host}") else c
                for c in cert.subject
            ]
            print(f"{orange(f'{item:<{width}}')} " f": {' '.join(cert.subject)}")
        elif "subject_alt_name" == item:
            for san in sorted(cert.sans):
                if host == str(san) and not matched_host:
                    # Our host arg matches an exact SAN
                    matched_host = True
                    print(f"{orange(f'{item:<{width}}')} " f": {bold(blue(san))}")
                elif (
                    str(san).endswith(re.sub("^[a-z1-9_-]+", "*", host))
                    and not matched_host
                ):
                    # Our host arg matches a wildcard SAN
                    matched_host = True
                    print(f"{orange(f'{item:<{width}}')} " f": {orange(san)}")
                else:
                    print(f"{orange(f'{item:<{width}}')} " f": {san}")
        elif "serial_number" == item:
            print(
                f"{orange(f'{item:<{width}}')} "
                f": {bold(blue(str(cert.serial_as_hex)))}"
            )
        elif "not_after" == item:
            warning = ""
            if cert.not_after <= tlsserial.helper.today:
                warning = f" {red('(expired!)')}"
            elif cert.not_after <= tlsserial.helper.next_14d:
                warning = f" {red('(expires within 14 days!)')}"
            elif cert.not_after <= tlsserial.helper.next_30d:
                warning = f" {red('(expires within 30 days!)')}"
            elif cert.not_after <= tlsserial.helper.next_90d:
                warning = f" {red('(expires within 90 days!)')}"
            print(f"{orange(f'{item:<{width}}')} : {cert.not_after}" + warning)
        elif "keytype_and_sig" == item:
            print(
                f"{orange(f'{item:<{width}}')} "
                f": {cert.key_type} {cert.key_bits}bits ({cert.sig_algo}) ({cert.sig_algo_params})"
            )
        elif "key_usage" in item:
            print(
                f"{orange(f'{item:<{width}}')} "
                f": {', '.join(sorted(cert.__getattribute__(item)))}"
            )
        else:
            print(f"{orange(f'{item:<{width}}')} " f": {cert.__getattribute__(item)}")


if __name__ == "__main__":
    cli()

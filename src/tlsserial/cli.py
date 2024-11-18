import logging
import os
from ssl import OPENSSL_VERSION

import click

from . import tlsserial, helper


# https://click.palletsprojects.com/en/8.1.x/quickstart/
@click.command()
@click.option(
    "--url",
    cls=helper.MutuallyExclusiveOption,
    mutually_exclusive=["file"],
    help="host || host:port || https://host:port/other",
)
@click.option(
    "--file",
    cls=helper.MutuallyExclusiveOption,
    mutually_exclusive=["url"],
    help="filename containing a PEM certificate",
)
@click.option("--debug", is_flag=True, type=bool, default=False, help="Debug logging")
@click.option(
    "--verbose", is_flag=True, type=bool, default=False, help="Verbose output"
)
def main(url, file, debug, verbose) -> None:
    """tlsserial groks X509 certificates for your pleasure"""
    default_level = "DEBUG" if debug else "INFO"
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOGLEVEL", default_level).upper()),
        format="[%(levelname)s] %(asctime)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.debug("Logging is set to DEBUG level")
    if url:
        tlsserial.handle_url(url, verbose)
    elif file:
        tlsserial.handle_file(file, verbose)
    else:
        click.echo(f"Library version : {OPENSSL_VERSION}")
        ctx = click.get_current_context()
        click.echo(ctx.get_help())

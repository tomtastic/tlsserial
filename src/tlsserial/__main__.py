"""
This file allows you to run the program directly from the python module:

    ~ $ python -m tlsserial --help

"""

import sys

from .cli import main

rc = 1
try:
    main()  # pylint: disable=no-value-for-parameter  # noqa
    rc = 0
except Exception as e:  # pylint: disable=broad-exception-caught
    print("Error:", e, file=sys.stderr)
sys.exit(rc)

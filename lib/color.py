""" Colour functions for wrapping strings """
from sys import __stdin__, __stdout__

# Styles
BOLD = "\x1b[1m"
END = "\x1b[0m"

# Amazon colours
SKY = "\x1b[38;2;32;116;213m"  # Blue
SMILE = "\x1b[38;2;255;153;0m"  # Orange
COSMOS = "\x1b[38;2;223;42;93m"  # Red

# Dont wrap with ANSI escape colour codes if we're not a TTY supporting that
IS_TTY_STDIN = __stdin__.isatty()
IS_TTY_STDOUT = __stdout__.isatty()


def bold(text: str) -> str:
    if IS_TTY_STDOUT:
        return BOLD + text + END
    else:
        return text


def blue(text: str) -> str:
    if IS_TTY_STDOUT:
        return SKY + text + END
    else:
        return text


def orange(text: str) -> str:
    if IS_TTY_STDOUT:
        return SMILE + text + END
    else:
        return text


def red(text: str) -> str:
    if IS_TTY_STDOUT:
        return COSMOS + text + END
    else:
        return text

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(order=True)
class NiceCertificate:
    """Class of objects with certificate details"""

    # Maybe we'd like to compare Certificate objects by notAfter field?
    sort_index: datetime = field(init=False, repr=False)
    not_after: datetime
    not_before: datetime
    chain: list = field(default_factory=list)
    issuer: list = field(default_factory=list)
    subject: list = field(default_factory=list)
    sans: list = field(default_factory=list)
    # There are many ways we might want to skin this cat
    serial_as_int: int = 0  #  0123456789
    serial_as_hex: str = field(init=False, repr=False)  #    075bcd15
    serial_as_hex_lower: str = field(init=False, repr=False)  #  0x075bcd15
    serial_as_hex_upper: str = field(init=False, repr=False)  #  0x075BCD15
    serial_as_hex_sep_colon: str = field(init=False, repr=False)  # 07:5B:CD:15
    serial_as_hex_sep_space: str = field(init=False, repr=False)  #   075B CD15
    # Of vague interest
    basic_constraints: dict = field(repr=True, default_factory=dict)
    key_usage: list = field(default_factory=list)
    ext_key_usage: list = field(default_factory=list)
    version: None | int = field(repr=True, default=None)
    key_type: None | str = field(default=None)
    key_bits: None | int = field(default=None)
    sig_algo: None | str = field(default=None)
    sig_algo_params: None | str = field(default=None)
    # Fun fields for CTF challenges
    key_factors: dict = field(repr=True, default_factory=dict)
    # Any CRLs mentioned
    crls: None | str = field(default=None)
    # OCSP / CaIssuer locations
    ocsp: None | str = field(default=None)
    ca_issuers: None | str = field(default=None)

    def __post_init__(self) -> None:
        """We set these keyed off the initialised values"""
        self.sort_index = self.not_after

        # Generate some other serialnumber styles
        self.serial_as_hex = str(hex(self.serial_as_int)[2:]).upper()
        # We always want to zero pad this hex number, if it's length isn't
        # divisible by 2.  eg. "0xa" should format as "0x0a"
        if divmod(len(self.serial_as_hex), 2)[1] == 1:
            self.serial_as_hex = self.serial_as_hex.zfill(len(self.serial_as_hex) + 1)

        self.serial_as_hex_lower = "0x" + self.serial_as_hex.lower()
        self.serial_as_hex_upper = "0x" + self.serial_as_hex.upper()

        self.serial_as_hex_sep_colon = ":".join(
            [
                self.serial_as_hex[i : i + 2]
                for i in range(0, len(self.serial_as_hex), 2)
            ]
        )

        self.serial_as_hex_sep_space = " ".join(
            [
                self.serial_as_hex[i : i + 4]
                for i in range(0, len(self.serial_as_hex), 4)
            ]
        )

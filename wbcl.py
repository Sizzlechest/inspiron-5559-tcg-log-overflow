#!/usr/bin/env python3
"""
wbcl.py - parse a Windows MeasuredBoot WBCL / TCG event log.

Reads C:\\Windows\\Logs\\MeasuredBoot\\*.log (raw firmware TCG event log, as
handed to Windows via the TCG2 protocol). Handles both the legacy SHA-1-only
TCG_PCClientPCREvent format and the TPM 2.0 crypto-agile TCG_PCR_EVENT2 format,
auto-detected from the Spec ID Event03 header.

Usage:
    python wbcl.py LOGFILE                 # per-PCR summary
    python wbcl.py LOGFILE --pcr 7         # full event listing for PCR 7
    python wbcl.py LOGFILE --pcr 7 --replay
    python wbcl.py LOGFILE --all           # every event, every PCR
    python wbcl.py *.log --summary-only    # compare many logs at a glance

Read-only. Touches nothing but the file you point it at.
"""

import argparse
import glob
import hashlib
import struct
import sys

# --- TCG algorithm registry (the subset that shows up in firmware logs) -----
ALG = {
    0x0004: ("SHA1", 20),
    0x000B: ("SHA256", 32),
    0x000C: ("SHA384", 48),
    0x000D: ("SHA512", 64),
    0x0012: ("SM3_256", 32),
}

HASHLIB = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA384": hashlib.sha384,
    "SHA512": hashlib.sha512,
}

EVENT_TYPES = {
    0x00000000: "EV_PREBOOT_CERT",
    0x00000001: "EV_POST_CODE",
    0x00000002: "EV_UNUSED",
    0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_SEPARATOR",
    0x00000005: "EV_ACTION",
    0x00000006: "EV_EVENT_TAG",
    0x00000007: "EV_S_CRTM_CONTENTS",
    0x00000008: "EV_S_CRTM_VERSION",
    0x00000009: "EV_CPU_MICROCODE",
    0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
    0x0000000B: "EV_TABLE_OF_DEVICES",
    0x0000000C: "EV_COMPACT_HASH",
    0x0000000D: "EV_IPL",
    0x0000000E: "EV_IPL_PARTITION_DATA",
    0x0000000F: "EV_NONHOST_CODE",
    0x00000010: "EV_NONHOST_CONFIG",
    0x00000011: "EV_NONHOST_INFO",
    0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
    0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
    0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION",
    0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES",
    0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    0x8000000B: "EV_EFI_HANDOFF_TABLES2",
    0x8000000C: "EV_EFI_VARIABLE_BOOT2",
    0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
    0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB",
    0x800000E2: "EV_EFI_SPDM_FIRMWARE_CONFIG",
}

SPEC_ID_SIG = b"Spec ID Event03\x00"

VARIABLE_EVENTS = {
    0x80000001,  # DRIVER_CONFIG
    0x80000002,  # BOOT
    0x8000000C,  # BOOT2
    0x800000E0,  # VARIABLE_AUTHORITY
}


class Event:
    __slots__ = ("index", "pcr", "etype", "digests", "data", "offset")

    def __init__(self, index, pcr, etype, digests, data, offset):
        self.index = index
        self.pcr = pcr
        self.etype = etype
        self.digests = digests      # {"SHA1": b"...", ...}
        self.data = data
        self.offset = offset

    @property
    def type_name(self):
        return EVENT_TYPES.get(self.etype, "UNKNOWN(0x%08X)" % self.etype)

    @property
    def variable_name(self):
        """Decode UEFI_VARIABLE_DATA.UnicodeName, if this is a variable event."""
        if self.etype not in VARIABLE_EVENTS:
            return None
        if len(self.data) < 32:
            return None
        try:
            name_len, data_len = struct.unpack_from("<QQ", self.data, 16)
            if name_len > 512:
                return None
            end = 32 + name_len * 2
            if end > len(self.data):
                return None
            return self.data[32:end].decode("utf-16-le")
        except Exception:
            return None

    @property
    def variable_guid(self):
        if self.etype not in VARIABLE_EVENTS or len(self.data) < 16:
            return None
        d1, d2, d3 = struct.unpack_from("<IHH", self.data, 0)
        rest = self.data[8:16]
        return "%08X-%04X-%04X-%s-%s" % (
            d1, d2, d3, rest[:2].hex().upper(), rest[2:].hex().upper()
        )

    @property
    def variable_data_len(self):
        if self.etype not in VARIABLE_EVENTS or len(self.data) < 32:
            return None
        try:
            _, data_len = struct.unpack_from("<QQ", self.data, 16)
            return data_len
        except Exception:
            return None

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


def parse(blob):
    """Return (events, header_info)."""
    events = []
    off = 0
    n = len(blob)
    header = {"format": "legacy", "algs": [("SHA1", 20)], "vendor_info": b""}

    def legacy_event(off, index):
        if off + 32 > n:
            return None, off
        pcr, etype = struct.unpack_from("<II", blob, off)
        digest = blob[off + 8: off + 28]
        (size,) = struct.unpack_from("<I", blob, off + 28)
        start = off + 32
        if start + size > n:
            return None, off
        data = blob[start:start + size]
        return Event(index, pcr, etype, {"SHA1": digest}, data, off), start + size

    # First event is ALWAYS in legacy format.
    first, off2 = legacy_event(0, 0)
    if first is None:
        raise ValueError("file too short or not a TCG event log")

    crypto_agile = first.etype == 0x00000003 and first.data.startswith(SPEC_ID_SIG)

    if crypto_agile:
        d = first.data
        (num_algs,) = struct.unpack_from("<I", d, 24)
        algs = []
        p = 28
        for _ in range(num_algs):
            alg_id, dsize = struct.unpack_from("<HH", d, p)
            name = ALG.get(alg_id, ("ALG_0x%04X" % alg_id, dsize))[0]
            algs.append((name, dsize))
            p += 4
        vendor_size = d[p]
        header.update({
            "format": "crypto-agile",
            "algs": algs,
            "spec_version": "%d.%d errata %d" % (d[21], d[20], d[22]),
            "platform_class": struct.unpack_from("<I", d, 16)[0],
            "vendor_info": d[p + 1: p + 1 + vendor_size],
        })
    events.append(first)
    off = off2
    index = 1

    if not crypto_agile:
        while off < n:
            ev, off = legacy_event(off, index)
            if ev is None:
                break
            events.append(ev)
            index += 1
        return events, header

    # crypto-agile body
    while off + 12 <= n:
        pcr, etype, count = struct.unpack_from("<III", blob, off)
        p = off + 12
        digests = {}
        bad = False
        for _ in range(count):
            if p + 2 > n:
                bad = True
                break
            (alg_id,) = struct.unpack_from("<H", blob, p)
            if alg_id not in ALG:
                # fall back to the header's declared size, if we can match it
                bad = True
                break
            name, dsize = ALG[alg_id]
            p += 2
            if p + dsize > n:
                bad = True
                break
            digests[name] = blob[p:p + dsize]
            p += dsize
        if bad or p + 4 > n:
            break
        (size,) = struct.unpack_from("<I", blob, p)
        p += 4
        if p + size > n:
            break
        events.append(Event(index, pcr, etype, digests, blob[p:p + size], off))
        off = p + size
        index += 1

    return events, header


def replay(events, pcr, bank):
    """Recompute a PCR by extension. EV_NO_ACTION is never extended."""
    h = HASHLIB.get(bank)
    if h is None:
        return None
    size = {"SHA1": 20, "SHA256": 32, "SHA384": 48, "SHA512": 64}[bank]
    cur = b"\x00" * size
    used = 0
    for ev in events:
        if ev.pcr != pcr or ev.etype == 0x00000003:
            continue
        d = ev.digests.get(bank)
        if d is None:
            continue
        cur = h(cur + d).digest()
        used += 1
    return cur, used


def describe(ev, bank):
    bits = ["[%3d] PCR[%2d] %-34s" % (ev.index, ev.pcr, ev.type_name)]
    name = ev.variable_name
    if name is not None:
        bits.append("var=%-14s" % ("'%s'" % name))
        vdl = ev.variable_data_len
        if vdl is not None:
            bits.append("vardata=%-7d" % vdl)
    d = ev.digests.get(bank)
    if d:
        bits.append(d.hex())
    bits.append("(%d bytes data @ 0x%X)" % (len(ev.data), ev.offset))
    return "  ".join(bits)


def report(path, args):
    with open(path, "rb") as f:
        blob = f.read()
    events, header = parse(blob)

    print("=" * 78)
    print("FILE   %s  (%d bytes)" % (path, len(blob)))
    print("FORMAT %s   banks in log: %s" % (
        header["format"], ", ".join("%s/%d" % a for a in header["algs"])))
    if header["format"] == "crypto-agile":
        print("SPEC   %s   platform class %d" % (
            header.get("spec_version"), header.get("platform_class")))
    print("EVENTS %d total" % len(events))

    banks = [a[0] for a in header["algs"]]
    primary = banks[0]

    per_pcr = {}
    for ev in events:
        per_pcr.setdefault(ev.pcr, []).append(ev)
    print()
    print("  PCR   events   event types present")
    for p in sorted(per_pcr):
        kinds = []
        for ev in per_pcr[p]:
            if ev.type_name not in kinds:
                kinds.append(ev.type_name)
        shown = ", ".join(k.replace("EV_EFI_", "").replace("EV_", "") for k in kinds[:6])
        if len(kinds) > 6:
            shown += ", +%d more" % (len(kinds) - 6)
        print("  %3d   %6d   %s" % (p, len(per_pcr[p]), shown))

    if args.summary_only:
        print()
        return

    targets = []
    if args.all:
        targets = sorted(per_pcr)
    elif args.pcr is not None:
        targets = [args.pcr]

    for p in targets:
        print()
        print("--- PCR[%d] -------------------------------------------------" % p)
        for ev in per_pcr.get(p, []):
            print(describe(ev, primary))
        if not per_pcr.get(p):
            print("  (no events)")

        if args.replay:
            for bank in banks:
                r = replay(events, p, bank)
                if r:
                    val, used = r
                    print("  replay %-7s over %d extends: %s" % (bank, used, val.hex().upper()))
    print()


def main():
    ap = argparse.ArgumentParser(description="Parse Windows MeasuredBoot WBCL logs.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--pcr", type=int, default=None, help="detail one PCR index")
    ap.add_argument("--all", action="store_true", help="detail every PCR")
    ap.add_argument("--replay", action="store_true", help="recompute PCR by extension")
    ap.add_argument("--summary-only", action="store_true")
    args = ap.parse_args()

    paths = []
    for pat in args.files:
        hits = sorted(glob.glob(pat))
        paths.extend(hits if hits else [pat])

    for path in paths:
        try:
            report(path, args)
        except Exception as e:
            print("=" * 78)
            print("FILE   %s" % path)
            print("ERROR  %s: %s" % (type(e).__name__, e))
            print()


if __name__ == "__main__":
    main()

# Dell Inspiron 5559 (BIOS 1.9.0): TCG event log buffer overflow

**Document revision:** 2 — 2026-09-12, post-verification. Sections 1–6.
Full narrative continues in [02-operations-open-questions.md](02-operations-open-questions.md).

**Status:** Workaround applied and verified. BitLocker sealed to PCR 7, 11 and unsealing cleanly.

## 1. Summary

Dell BIOS 1.9.0 on the Inspiron 5459/5559/5759 platform allocates a fixed TCG event log buffer of approximately 32,768 bytes. When appending the next measurement record would exceed that buffer, the firmware **silently stops writing log records while continuing to extend TPM PCRs**. The event log and the TPM therefore diverge.

Observable consequences:

- `manage-bde -protectors -add C: -tpm` fails with `0x80310002 / FVE_E_NO_TPM_BIOS`
- `msinfo32` reports `PCR7 Configuration: Binding Not Possible`
- `tpmtool getdeviceinformation` reports `PCR7 Binding State: 0`
- BitLocker-API Event 813 names the first unwritten variable
- BitLocker-API Event 893 emits a filtered PCR[7] log
- Event 1796: "The BIOS did not correctly communicate with the Trusted Platform Module (TPM)"

Triggered when Windows added three certificates to `db` on 2026-08-06 (`db` 3,143 → 7,636 bytes) while a full Microsoft `dbx` was present. Not specific to `db` or the 2023 certificates: the same firmware truncated in June 2025 under a different variable mix.

**Resolution:** delete `dbx` via firmware setup. Verified working.

## 2. Platform

Inspiron 5559, SKU `06B2`, board `0WTXH9` A00, i5-6200U, BIOS **1.9.0** (2020-09-07, final), UEFI Secure Boot On, Intel PTT TPM 2.0 (`INTC` 303.12.0.0, SPT). Windows 10 IoT Enterprise LTSC 2021 build 19044.7725. TPM health normal throughout. The TPM is not implicated.

## 3. Log format

All 127 MeasuredBoot logs use legacy `TCG_PCClientPCREvent` (SHA-1 only, no Spec ID Event03). Not the cause.

Post-fix complete firmware sequence (log `0000000096`, 2026-09-12 21:43:37) is 30 records ending at byte **17,337**, including empty `dbx` (payload 0) and `EV_EFI_VARIABLE_AUTHORITY` on PCR 7. Empty variables are still measured.

## 4. Buffer boundary

```
limit >= 32,595   (log 1 wrote this much)
limit <  32,975   (log 1 refused the next 380-byte record)
=>  32,595 <= buffer < 32,975
```

**32,768 (32 KiB) is the only round value in that window.**

June 2025 logs truncated with `db`=3,143 and `dbx`=25,051. Constraint is total size.

In the truncated state, SHA-1 replay of logged PCR[7] records does not match the TPM PCR[7] from Event 893. Firmware continues extending after it stops logging.

Post-fix, Event 893 no longer fires. Agreement is proven by BitLocker accepting a PCR 7, 11 seal.

`EV_EFI_VARIABLE_AUTHORITY` is absent from all 126 pre-fix logs, including healthy complete ones, and present post-fix. Why is an open question.

## 5. Verified before / after (same BIOS, same db, only dbx deleted)

| | Before (log 89) | After (log 96) |
|---|---|---|
| dbx | 23,207 bytes | undefined |
| Firmware records | 15 | 30 |
| EV_SEPARATOR | 0 | 8 |
| Firmware portion | 13,574 truncated | 17,337 complete |
| tpmtool PCR7 | 0 | 3 |
| msinfo32 | Binding Not Possible | Bound |
| TPM protector | 0x80310002 | PCR 7, 11 |

Binding ladder: 0 = Not Possible, 2 = Possible, 3 = Bound.

## 6. Size budget

```
32,768 - 13,048 (through db) - 4,219 (tail) - 70 (dbx record overhead) = 15,431 bytes max dbx payload
```

Current full Microsoft dbx is 23,207 bytes — 7,776 over budget.

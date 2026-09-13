# Inspiron 5459/5559/5759: TCG event log buffer overflow breaks measured boot

Dell BIOS **1.9.0** (final firmware for Inspiron 5459 / 5559 / 5759) allocates a fixed TCG event log of about **32,768 bytes**. When the next measurement will not fit, the firmware **stops writing the log but keeps extending TPM PCRs**. Windows then cannot validate any PCR.

This is not a dead TPM and not Dell’s usual “PCR7 Binding Not Possible because of an option ROM” article.

## Symptoms

- `manage-bde -protectors -add C: -tpm` fails with `0x80310002` / `FVE_E_NO_TPM_BIOS`
- `msinfo32` → PCR7 Configuration: **Binding Not Possible**
- `tpmtool getdeviceinformation` → PCR7 Binding State: **0**
- BitLocker-API Event **813** names the first unwritten variable (usually `'dbx'`)
- BitLocker-API Event **893** attaches a filtered PCR[7] log
- TPM-WMI Event **1796**: “The BIOS did not correctly communicate with the Trusted Platform Module (TPM)”

Trigger on the documented machine: Windows added the 2023 Secure Boot certificates to `db` on 2026-08-06 (`db` 3,143 → 7,636 bytes) while a full Microsoft `dbx` (~23 KB) was already present. The same firmware also truncated in June 2025 with a smaller `db` and a larger `dbx`. The constraint is **total measured size**, not a specific certificate.

## Workaround (verified)

1. Suspend BitLocker if the volume is already encrypted:  
   `manage-bde -protectors -disable C: -RebootCount 0`
2. Firmware setup → Secure Boot → Expert Key Management → Custom Mode → **dbx → Delete**
3. Do **not** clear the TPM. Do **not** Delete All Keys.
4. Reboot. Confirm `Get-SecureBootUEFI dbx` fails with `0xC0000100`, and `msinfo32` shows Binding Possible / Bound.
5. Re-enable the TPM protector if you suspended it.

Empty `dbx` is a security trade-off (no revocations) in exchange for a working PCR 7,11 seal. BIOS 1.9.0 will not get a larger log buffer.

Windows Secure Boot servicing will try to put the full `dbx` back. On the documented machine this was blocked with:

```powershell
$k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
New-ItemProperty -Path $k -Name HighConfidenceOptOut -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path $k -Name AvailableUpdates -Value 0
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
```

If a later update writes `dbx` anyway: suspend BitLocker, delete `dbx` in firmware again, resume.

## Files

| File | What it is |
|---|---|
| [inspiron-5559-tcg-buffer-overflow.md](inspiron-5559-tcg-buffer-overflow.md) | Full RCA: corpus, buffer bracket, PCR replay vs TPM, before/after log 89 vs 96, size budget, servicing controls |
| [wbcl.py](wbcl.py) | Stdlib Python 3 parser for Windows MeasuredBoot WBCL logs (legacy SHA-1 and crypto-agile) |

```text
python wbcl.py path\to\*.log --summary-only
python wbcl.py path\to\0000000096-0000000000.log --all --replay
```

Raw logs are `C:\Windows\Logs\MeasuredBoot\*.log` (System attribute: use `dir -Force`). `tpm2_eventlog` will not parse this firmware’s logs; they have no Spec ID Event03 header.

## Binding-state ladder (measured)

| tpmtool PCR7 Binding State | msinfo32 | Condition |
|---|---|---|
| 0 | Binding Not Possible | truncated log |
| 2 | Binding Possible | complete log, nothing sealed |
| 3 | Bound | TPM protector sealed to PCR 7, 11 |

## What this is not

Dell KB articles that explain PCR7 Binding Not Possible via third-party option ROM / discrete GPU are a different path. This machine flipped Binding Not Possible → Bound by deleting one UEFI variable, with no firmware or hardware change.

## License

Write-up and `wbcl.py` are MIT. See [LICENSE](LICENSE).

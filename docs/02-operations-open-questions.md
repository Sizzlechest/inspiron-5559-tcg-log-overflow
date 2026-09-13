# Operations, hypotheses, and open questions

Continues [01-summary-evidence-fix.md](01-summary-evidence-fix.md). Document revision 2 — 2026-09-12.

## 7. Security trade-off as accepted

The machine runs with **dbx undefined** — no Secure Boot revocations.

**Lost:** PCA 2011 revocation and ~400 binary hash revocations (BlackLotus-era loaders).
**Retained:** TPM-sealed BitLocker on PCR 7, 11.

A minimal PCA-2011-only ESL (~1.5 KB) was built but Dell Expert Key Management on BIOS 1.9.0 rejected ESL/DER/CER ("signed and formatted properly"). Setup Mode requires Delete All Keys — not attempted on an encrypted volume.

PCA 2011 expires 2026-10-19.

## 8. Operational controls applied

```powershell
$k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
New-ItemProperty -Path $k -Name HighConfidenceOptOut -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path $k -Name AvailableUpdates -Value 0
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
```

`HighConfidenceOptOut` is the durable layer. The scheduled-task disable is secondary; component servicing can re-register the task during a CU.

This platform cannot complete Secure Boot servicing anyway (Event 1803, no PK-signed KEK).

### Monthly check (after each Patch Tuesday)

```powershell
$k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
try { (Get-SecureBootUEFI dbx).bytes.Length } catch { "dbx: undefined" }
(Get-SecureBootUEFI db).bytes.Length
dir C:\Windows\Logs\MeasuredBoot -Force | Sort-Object LastWriteTime | Select -Last 1 Name, Length
tpmtool getdeviceinformation | findstr /i "PCR7"
Get-ItemProperty $k | Select AvailableUpdates, HighConfidenceOptOut
(Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update").State
manage-bde -status C: | Select-String "Protection Status"
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1034,1036,1037,1044,1045; StartTime=(Get-Date).AddDays(-40)} `
  -ErrorAction SilentlyContinue | Select TimeCreated, Id
```

Recovery if dbx returns: suspend BitLocker, delete dbx in firmware setup, resume. Do not clear the TPM. Do not Delete All Keys.

## 9. Hypotheses tested and falsified

- PCR7 Binding Not Possible is not a permanent hardware limit — it became Bound after deleting one UEFI variable.
- PC Client Version 1.00 is not a TPM 1.2 incompatibility. This machine now reports 1.00 and Bound together.
- SHA-1-only log format is not the cause.
- Firmware stops *logging*, not measuring. PCR extension continues.
- Truncation is not PCR[7]-specific. Every firmware record after the overflow point is lost.
- Event 893 cannot confirm the fix; it only fires when the log is invalid.
- HSTI / Modern Standby failure in msinfo32 is unrelated to manual BitLocker.
- No BitLocker GPO (`HKLM\SOFTWARE\Policies\Microsoft\FVE` does not exist).

## 10. Open questions

1. Exact buffer size (bracketed [32,595, 32,975); 32,768 inferred).
2. Whether ~32 KiB is a Dell/Insyde allocation choice.
3. Why EV_EFI_VARIABLE_AUTHORITY appears only post-fix (absent from all 126 pre-fix logs, including healthy ones).
4. Which extends were applied but not logged.
5. Whether this BIOS accepts any unsigned dbx append.
6. How many 5459/5559/5759 units are affected.
7. Whether other Dell consumer PCR7 Binding Not Possible reports are the same buffer bug.

## 11. Parse logs

```
python wbcl.py path\to\*.log --summary-only
python wbcl.py path\to\0000000096-0000000000.log --all --replay
```

Raw logs: `C:\Windows\Logs\MeasuredBoot\*.log` (`dir -Force`; System attribute). `tpm2_eventlog` will not parse these files (no Spec ID Event03 header).

Relevant IDs: BitLocker 813/834/893/897; TPM-WMI 1034/1036/1037/1044/1045/1796/1803.

## 12. Vendor context

Dell KB 000390990: platforms EOSL before 2026-01-01 get no BIOS for the 2023 certificate transition. This Inspiron family is not on Dell KB 000347876.

Microsoft High Confidence classified this device's bucket for *variable-write success*, which is what overflowed the log. That classification does not mean measured boot still works.

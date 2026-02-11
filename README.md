# Symmetricom GPS Rollover Firmware Fix

Author: zombu2  
Updated: 2026-02-11

This repository contains a validated firmware patch bundle and deployment workflow for correcting GPS week-rollover date behavior on compatible Symmetricom XLi units.

The package includes:

- patched software image (`192-8001-branchstub-17da20-lencrc.bin`)
- stock rollback software image (`192-8001V1_106.bin`)
- stock rollback filesystem image (`192-8002V1_106.fs`)
- deployment script (`xli_autopatch_deploy.py`)
- detailed operational documents (quickstart + engineering report)
- SHA-256 integrity manifest (`SHA256SUMS.txt`)

## 1) Compatibility and scope

This repository is for the XLi software/image family represented by these files:

- `192-8001V1_106.bin` (application software)
- `192-8002V1_106.fs` (filesystem image)

If your unit runs a different software family, do not assume direct compatibility.

## 2) Repository layout

- `192-8001-branchstub-17da20-lencrc.bin`  
  Patched software image (target patch payload).
- `192-8001.bin`  
  Staged software filename used by NI burn flow.
- `:192-8001.bin`  
  Colon-prefixed staged filename for XLi FTP fetch quirk.
- `192-8001V1_106.bin`  
  Stock software rollback image.
- `192-8002V1_106.fs`  
  Stock filesystem rollback image.
- `xli_autopatch_deploy.py`  
  Automated deploy script (stage, burn, optional reboot, logging).
- `AUTOPATCH_USAGE.md`  
  Operator quickstart (copy/paste workflow).
- `XLi_Autopatch_Deploy_Quickstart.pdf`  
  PDF quickstart.
- `XLi_GPS_Rollover_Patch_Instructions.md`  
  Manual burn instructions.
- `XLi_GPS_Rollover_Patch_Instructions.pdf`  
  PDF manual instructions.
- `XLi_GPS_Rollover_Engineering_Report.md`  
  Full technical report (RE, failures, what worked).
- `XLi_GPS_Rollover_Engineering_Report.pdf`  
  PDF technical report.
- `xli_branchstub_17da20_report.json`  
  Patch metadata for the validated image.
- `SHA256SUMS.txt`  
  File integrity manifest.

## 3) Prerequisites

### 3.1 Network and access

- NI/telnet access to target XLi.
- Known NI username/password.
- FTP server reachable from XLi.

### 3.2 Local toolchain

- Python 3
- `gh` (optional, for repository operations)

## 4) Integrity validation (required)

From repository root:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

All lines must return `OK`.

## 5) FTP server setup

XLi burn path fetches image files over FTP. Keep FTP root set to this repository directory.

## 5.1 Option A: temporary Python FTP server (anonymous)

```bash
python3 -m pip install --user pyftpdlib
python3 -m pyftpdlib -p 21 -w -d .
```

Leave this terminal running during deployment.

## 5.2 Option B: vsftpd (Linux)

Example `/etc/vsftpd.conf`:

```conf
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=NO
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/path/to/Symmetricom-Gps-Rollover-firmware-fix
no_anon_password=YES
pasv_enable=NO
```

Then:

```bash
sudo systemctl restart vsftpd
sudo systemctl status vsftpd
```

## 6) Automated deployment (recommended)

## 6.1 Basic command

```bash
python3 xli_autopatch_deploy.py \
  --target-ip <TARGET_IP> \
  --ftp-host <FTP_HOST_IP> \
  --user <USER> \
  --password <PASSWORD>
```

## 6.2 What the script does

1. Verifies patched image SHA-256.
2. Stages both software names used by XLi fetch flow:
   - `192-8001.bin`
   - `:192-8001.bin`
3. Logs in via NI/telnet.
4. Executes burn flow (`BH` then `bu`).
5. Optionally reboots and checks telnet reachability.
6. Writes a deployment log under `./logs/`.

## 6.3 Useful options

- `--no-stage`  
  Skip staging copy to FTP root names.
- `--no-reboot`  
  Skip reboot after successful burn.
- `--wait-reboot <seconds>`  
  Delay before post-reboot reachability check.
- `--image-source <file>`  
  Use alternate patch image.
- `--expected-sha256 <hash>`  
  Enforce exact source file hash.
- `--log-file <path>`  
  Write log to explicit path.

## 7) Manual deployment (NI shell)

If needed, perform burn manually.

## 7.1 Stage filenames in FTP root

```bash
cp -f 192-8001-branchstub-17da20-lencrc.bin 192-8001.bin
cp -f 192-8001-branchstub-17da20-lencrc.bin :192-8001.bin
```

## 7.2 Burn commands in NI monitor

- `F100 BH:<FTP_HOST_IP>,192-8001.bin`
- `F100 bu`
- `F100 BASET AUTO`

## 8) Post-burn verification

## 8.1 Patch marker verification

Use your existing status tool/check flow and confirm:

- `site_is_branch = true`
- `site_branch_target = 0x0017da20`
- `stub_pattern_ok = true`

## 8.2 Date path check

In shell:

- `d 0x0031a40c,16,1`

Validate date behavior at runtime/after lock transitions and after reboot.

## 8.3 Service health check

Confirm:

- NI/telnet reachable
- web UI/auth functional

## 9) Rollback procedure

Use rollback if patch behavior is not acceptable.

## 9.1 Software rollback

```bash
cp -f 192-8001V1_106.bin 192-8001.bin
cp -f 192-8001V1_106.bin :192-8001.bin
```

Then in NI:

- `F100 BH:<FTP_HOST_IP>,192-8001.bin`
- `F100 bu`
- `F100 BASET AUTO`

## 9.2 Filesystem rollback (if web/auth is broken)

In NI:

- `F100 BH:<FTP_HOST_IP>,192-8002V1_106.fs`
- `F100 bf`
- reboot again

## 10) Troubleshooting

## 10.1 Burn fails or image not fetched

- Confirm FTP host is reachable from XLi.
- Confirm both staged names exist:
  - `192-8001.bin`
  - `:192-8001.bin`
- Re-run hash verification.

## 10.2 Web login loops or UI is broken after burn

- Roll back software image first.
- If still broken, roll back filesystem image and reboot.

## 10.3 Date still incorrect after reboot

- Re-check patch marker state.
- Re-check lock state behavior and raw date bytes.
- If markers are absent, unit is effectively on stock path and needs redeploy or rollback decision.

## 11) Engineering context

A full reverse-engineering and operational timeline is provided in:

- `XLi_GPS_Rollover_Engineering_Report.md`
- `XLi_GPS_Rollover_Engineering_Report.pdf`

That report includes:

- firmware decomposition and mapping
- hidden behavior findings
- failed attempts and why they failed
- validated patchpoint path
- recovery and reproducibility data

## 12) Disclaimer

This repository is intended for controlled engineering use on compatible systems with known recovery access. Validate behavior on non-production equipment first.

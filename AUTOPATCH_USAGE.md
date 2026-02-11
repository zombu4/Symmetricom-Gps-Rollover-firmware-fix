# XLi GPS Rollover Patch Quickstart (Operator Guide)

Author: zombu2
Last updated: 2026-02-11

This guide is copy/paste oriented. Follow in order.

## 1) What this package contains

- `192-8001-branchstub-17da20-lencrc.bin` (patched software image)
- `192-8001V1_106.bin` (stock software rollback)
- `192-8002V1_106.fs` (stock filesystem rollback)
- `xli_autopatch_deploy.py` (automatic deploy tool)
- `SHA256SUMS.txt` (integrity checks)

## 2) Preconditions

- XLi NI IP is reachable on telnet port 23.
- XLi credentials are known.
- FTP server is reachable by the XLi.
- Only one active telnet session is used during burn.

## 3) Start in the bundle folder

```bash
cd /path/to/XLi_patch_bundle_2026-02-11
```

## 4) Verify file integrity

```bash
shasum -a 256 -c SHA256SUMS.txt
```

Expected: every line ends with `OK`.

## 5) FTP server setup (anonymous / no user/pass)

Choose one option.

### Option A: macOS built-in python FTP server (quick temporary setup)

```bash
python3 -m pip install --user pyftpdlib
python3 -m pyftpdlib -p 21 -w -d .
```

Keep this terminal open while deploying.

### Option B: vsftpd (Linux)

Create `/etc/vsftpd.conf` with:

```conf
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=NO
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/path/to/XLi_patch_bundle_2026-02-11
no_anon_password=YES
pasv_enable=NO
```

Then:

```bash
sudo systemctl restart vsftpd
sudo systemctl status vsftpd
```

## 6) Run automatic patch deployment

```bash
python3 xli_autopatch_deploy.py \
  --target-ip 10.0.10.123 \
  --ftp-host 10.0.10.48 \
  --user operator \
  --password janus
```

What it does:

- Verifies patched image SHA-256.
- Stages both required names for XLi FTP fetch quirk:
  - `192-8001.bin`
  - `:192-8001.bin`
- Logs in to NI telnet.
- Runs burn commands (`BH` then `bu`).
- Optionally reboots and checks telnet comes back.
- Writes a deploy log under `./logs/`.

## 7) Post-burn verification

From NI shell, confirm:

- Date behavior is corrected after lock path transitions.
- Branch/stub patch state is present.
- UI login still works.

Recommended checks:

```bash
python3 /path/to/xli_patch_rollover.py --host 10.0.10.123 --user operator --password janus --status-only --target-year 2026
```

## 8) Rollback (if needed)

### Rollback software (stock)

```bash
cp -f 192-8001V1_106.bin 192-8001.bin
cp -f 192-8001V1_106.bin :192-8001.bin
```

Then in NI:

- `F100 BH:<ftp-host>,192-8001.bin`
- `F100 bu`
- `F100 BASET AUTO`

### Rollback filesystem (if web UI/auth is damaged)

In NI:

- `F100 BH:<ftp-host>,192-8002V1_106.fs`
- `F100 bf`
- reboot again

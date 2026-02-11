# XLi GPS Rollover Patch Instructions

Author: zombu2
Last updated: 2026-02-11

## 1) Scope

This procedure applies the validated branch-stub GPS rollover patch image to a compatible XLi unit and verifies behavior after reboot.

## 2) Files required

- `192-8001-branchstub-17da20-lencrc.bin` (patched software)
- `192-8001V1_106.bin` (software rollback)
- `192-8002V1_106.fs` (filesystem rollback)
- `SHA256SUMS.txt`

## 3) Pre-checks

1. Enter bundle directory:

```bash
cd ~/FTP/XLi_patch_bundle_2026-02-11
```

2. Verify hashes:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

All lines must report `OK`.

## 4) FTP server requirements

- XLi must be able to reach the FTP host.
- Anonymous/no-password FTP is acceptable.
- Keep the FTP root set to the bundle folder.

Temporary Python FTP server example:

```bash
python3 -m pip install --user pyftpdlib
python3 -m pyftpdlib -p 21 -w -d .
```

## 5) Stage image names for XLi fetch behavior

```bash
cp -f 192-8001-branchstub-17da20-lencrc.bin 192-8001.bin
cp -f 192-8001-branchstub-17da20-lencrc.bin :192-8001.bin
```

## 6) Burn from NI monitor

In NI telnet session:

- `F100 BH:<FTP_HOST_IP>,192-8001.bin`
- `F100 bu`

Expected signature includes successful programming and no sector readback failures.

## 7) Reboot

- `F100 BASET AUTO`

## 8) Post-burn validation

1. Confirm patch markers with status tool:

```bash
python3 xli_patch_rollover.py --host <TARGET_IP> --user <USER> --password <PASSWORD> --status-only --target-year 2026
```

Expected fields:

- `site_is_branch = true`
- `site_branch_target = 0x0017da20`
- `stub_pattern_ok = true`

2. Confirm date bytes in shell:

- `d 0x0031a40c,16,1`

3. Confirm UI and telnet both function after reboot.

## 9) Rollback (if needed)

Software rollback:

```bash
cp -f 192-8001V1_106.bin 192-8001.bin
cp -f 192-8001V1_106.bin :192-8001.bin
```

Then burn software again (`BH` + `bu`) and reboot.

Filesystem rollback (if web/auth behavior is broken):

- `F100 BH:<FTP_HOST_IP>,192-8002V1_106.fs`
- `F100 bf`
- reboot again

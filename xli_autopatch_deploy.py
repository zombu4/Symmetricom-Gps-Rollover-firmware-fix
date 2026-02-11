#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import shutil
import socket
import telnetlib
import time
from pathlib import Path

DEFAULT_PATCH_SHA = "ace2ccc1ea9a72d76a2f454363a84dcee8477c7a97a0c1576cbfbd6b0b29fa33"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_port(host: str, port: int, timeout_s: float) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return True
        except OSError:
            time.sleep(1.5)
    return False


class XliTelnet:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tn = telnetlib.Telnet(host, port, timeout)

    def read_until_any(self, pats: list[bytes], timeout: float | None = None) -> bytes:
        end = time.time() + (timeout if timeout is not None else self.timeout)
        buf = b""
        while time.time() < end:
            chunk = self.tn.read_very_eager()
            if chunk:
                buf += chunk
                for p in pats:
                    if p in buf:
                        return buf
            time.sleep(0.05)
        raise TimeoutError(f"Timeout waiting for {pats!r}. Tail={buf[-300:]!r}")

    def login(self, user: str, password: str) -> str:
        out = self.read_until_any([b"USER NAME:"], timeout=12)
        self.tn.write(user.encode("ascii") + b"\n")
        out += self.read_until_any([b"PASSWORD:"], timeout=12)
        self.tn.write(password.encode("ascii") + b"\n")
        out += self.read_until_any([b">", b"LOGIN SUCCESSFUL"], timeout=12)
        self.tn.write(b"\n")
        out += self.read_until_any([b">"], timeout=8)
        return out.decode("latin1", errors="replace")

    def cmd(self, text: str, wait_for: bytes = b">", timeout: float = 20.0) -> str:
        self.tn.write(text.encode("ascii") + b"\n")
        out = self.read_until_any([wait_for], timeout=timeout)
        return out.decode("latin1", errors="replace")

    def burn(self, ftp_host: str, image_name: str) -> tuple[bool, str]:
        log = []
        log.append(self.cmd(f"F100 BH:{ftp_host},{image_name}", wait_for=b">", timeout=30.0))
        self.tn.write(b"F100 bu\n")
        out = self.read_until_any(
            [b"FLASH SUCCESSFULLY PROGRAMMED", b"UNSUCCESSFUL ATTEMPT", b"TOO MANY UNSUCCESSFUL", b"ERR"],
            timeout=900.0,
        )
        text = out.decode("latin1", errors="replace")
        log.append(text)
        ok = "FLASH SUCCESSFULLY PROGRAMMED" in text
        # clear prompt if present
        try:
            log.append(self.read_until_any([b">"], timeout=5).decode("latin1", errors="replace"))
        except Exception:
            pass
        return ok, "\n".join(log)

    def reboot(self) -> str:
        try:
            return self.cmd("F100 BASET AUTO", wait_for=b"WAIT", timeout=20.0)
        except Exception:
            # unit may disconnect quickly, that's acceptable
            return ""

    def close(self) -> None:
        try:
            self.tn.write(b"quit\n")
            time.sleep(0.2)
        except Exception:
            pass
        try:
            self.tn.close()
        except Exception:
            pass


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Stage and deploy XLi GPS rollover patch image via NI telnet")
    ap.add_argument("--target-ip", default="10.0.10.123", help="XLi NI IP address")
    ap.add_argument("--target-port", type=int, default=23)
    ap.add_argument("--user", default="operator")
    ap.add_argument("--password", default="janus")
    ap.add_argument("--ftp-host", default="10.0.10.48", help="FTP server IP reachable by XLi")
    ap.add_argument("--ftp-root", default=str(script_dir), help="Local FTP server root path used for staging")
    ap.add_argument(
        "--image-source",
        default=str(script_dir / "192-8001-branchstub-17da20-lencrc.bin"),
        help="Patched software image file to deploy",
    )
    ap.add_argument("--image-name", default="192-8001.bin", help="Filename XLi should request from FTP")
    ap.add_argument("--expected-sha256", default=DEFAULT_PATCH_SHA)
    ap.add_argument("--no-stage", action="store_true", help="Skip copying source image into FTP root names")
    ap.add_argument("--no-reboot", action="store_true", help="Skip reboot after successful burn")
    ap.add_argument("--wait-reboot", type=int, default=40, help="Seconds to wait before post-reboot reachability check")
    ap.add_argument("--log-file", default="", help="Optional explicit log path")
    args = ap.parse_args()

    ftp_root = Path(args.ftp_root).expanduser().resolve()
    src = Path(args.image_source).expanduser().resolve()
    dst_main = ftp_root / args.image_name
    dst_colon = ftp_root / f":{args.image_name}"

    if not src.exists():
        raise SystemExit(f"image-source not found: {src}")

    src_sha = sha256_file(src)
    if args.expected_sha256 and src_sha.lower() != args.expected_sha256.lower():
        raise SystemExit(
            f"source sha mismatch: got {src_sha}, expected {args.expected_sha256}. "
            "Refusing to deploy wrong image."
        )

    if not args.no_stage:
        shutil.copy2(src, dst_main)
        shutil.copy2(src, dst_colon)

    main_sha = sha256_file(dst_main)
    colon_sha = sha256_file(dst_colon)

    if main_sha != src_sha or colon_sha != src_sha:
        raise SystemExit("staging verification failed: ftp root image hashes do not match source")

    ts = time.strftime("%Y%m%d-%H%M%S")
    default_log_dir = script_dir / "logs"
    log_path = Path(args.log_file).expanduser().resolve() if args.log_file else (default_log_dir / f"xli_autopatch_deploy_{ts}.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append(f"target={args.target_ip}:{args.target_port}")
    lines.append(f"ftp_host={args.ftp_host}")
    lines.append(f"source={src}")
    lines.append(f"source_sha256={src_sha}")
    lines.append(f"staged_main={dst_main} sha256={main_sha}")
    lines.append(f"staged_colon={dst_colon} sha256={colon_sha}")

    if not wait_port(args.target_ip, args.target_port, timeout_s=25):
        raise SystemExit(f"target {args.target_ip}:{args.target_port} not reachable before deploy")

    cli = XliTelnet(args.target_ip, args.target_port, timeout=12.0)
    try:
        lines.append("--- login ---")
        lines.append(cli.login(args.user, args.password))
        lines.append("--- burn ---")
        ok, burn_log = cli.burn(args.ftp_host, args.image_name)
        lines.append(burn_log)
        if not ok:
            lines.append("result=FAILED")
            log_path.write_text("\n".join(lines), encoding="latin1")
            print(log_path)
            raise SystemExit(2)

        lines.append("result=SUCCESS")
        if not args.no_reboot:
            lines.append("--- reboot ---")
            lines.append(cli.reboot())
    finally:
        cli.close()

    if not args.no_reboot:
        time.sleep(max(args.wait_reboot, 5))
        up = wait_port(args.target_ip, args.target_port, timeout_s=40)
        lines.append(f"post_reboot_telnet_up={int(up)}")

    log_path.write_text("\n".join(lines), encoding="latin1")
    print(log_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

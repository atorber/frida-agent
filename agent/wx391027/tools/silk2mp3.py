#!/usr/bin/env python3
"""WeChat SILK -> MP3 helper for Frida agent.
Usage: python silk2mp3.py <input.silk> <output.mp3> [sample_rate=24000] [ffmpeg]
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: silk2mp3.py <input.silk> <output.mp3> [sr] [ffmpeg]", file=sys.stderr)
        return 2

    silk_path = sys.argv[1]
    mp3_path = sys.argv[2]
    sr = int(sys.argv[3]) if len(sys.argv) > 3 else 24000
    ffmpeg = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("FFMPEG", "ffmpeg")

    if not os.path.isfile(silk_path):
        print(f"silk not found: {silk_path}", file=sys.stderr)
        return 1

    try:
        import pysilk
    except ImportError:
        print("pysilk not installed: pip install silk-python", file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(os.path.abspath(mp3_path)) or ".", exist_ok=True)

    raw = open(silk_path, "rb").read()
    # WeChat MediaMSG Buf often has a leading 0x02 before #!SILK_V3
    if raw.startswith(b"\x02#!SILK_V3"):
        raw = raw[1:]
    if not raw.startswith(b"#!SILK_V3"):
        print("not a SILK stream (missing #!SILK_V3 header)", file=sys.stderr)
        return 1

    fd, pcm_path = tempfile.mkstemp(suffix=".pcm")
    os.close(fd)
    silk_tmp = None
    try:
        # pysilk.decode requires BinaryIO, not path strings
        fd_s, silk_tmp = tempfile.mkstemp(suffix=".silk")
        os.close(fd_s)
        with open(silk_tmp, "wb") as f:
            f.write(raw)

        with open(silk_tmp, "rb") as fin, open(pcm_path, "wb") as fout:
            pysilk.decode(fin, fout, sr)

        if not os.path.isfile(pcm_path) or os.path.getsize(pcm_path) <= 0:
            print("pcm not produced", file=sys.stderr)
            return 1

        cmd = [
            ffmpeg,
            "-y",
            "-f",
            "s16le",
            "-ar",
            str(sr),
            "-ac",
            "1",
            "-i",
            pcm_path,
            "-codec:a",
            "libmp3lame",
            "-q:a",
            "2",
            mp3_path,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr or r.stdout, file=sys.stderr)
            return r.returncode or 1
        if not os.path.isfile(mp3_path) or os.path.getsize(mp3_path) <= 0:
            print("mp3 not produced", file=sys.stderr)
            return 1
        print(mp3_path)
        return 0
    except Exception as e:
        print(f"silk2mp3 failed: {e}", file=sys.stderr)
        return 1
    finally:
        for p in (pcm_path, silk_tmp):
            if not p:
                continue
            try:
                os.remove(p)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())

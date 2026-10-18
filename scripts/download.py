"""YouTube Proxy worker: validate inputs, decrypt selected cookies, download and report.

No workflow-dispatch values are interpolated into shell commands. Cookie secrets
are confined to a private temporary file that is deleted before artifact upload.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse


def boolean(value):
    return value is True or str(value).lower() == "true"


def validate(inputs):
    job_id = str(inputs.get("job_id", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", job_id):
        raise ValueError("Invalid job ID")
    url = str(inputs.get("url", ""))
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port or len(url) > 2000:
        raise ValueError("A YouTube HTTPS URL is required")
    if parsed.hostname not in {"www.youtube.com", "youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be"}:
        raise ValueError("Only YouTube URLs are accepted")
    params = parse_qs(parsed.query)
    path = unquote(parsed.path, errors="strict")
    if parsed.hostname == "youtu.be":
        video_id = path.lstrip("/")
        if not re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id):
            raise ValueError("Invalid video ID")
        params["v"] = [video_id]
        path = "/watch"
    elif path == "/watch":
        if not re.fullmatch(r"[A-Za-z0-9_-]{11}", params.get("v", [""])[0]):
            raise ValueError("Invalid video ID")
    elif path == "/playlist":
        if not re.fullmatch(r"[A-Za-z0-9_-]+", params.get("list", [""])[0]):
            raise ValueError("Invalid playlist ID")
    elif not (
        re.fullmatch(r"/(shorts|live|embed)/[A-Za-z0-9_-]{11}/?", path)
        or re.fullmatch(r"/(channel|user|c)/[A-Za-z0-9_.-]+(/(videos|shorts|streams))?/?", path)
        or re.fullmatch(r"/@[\w.-]+(/(videos|shorts|streams))?/?", path, re.UNICODE)
    ):
        raise ValueError("URL must point to a video, playlist or channel")
    fmt = inputs.get("format", "mp4")
    quality = str(inputs.get("quality", "720"))
    mode = inputs.get("mode", "single")
    count = int(inputs.get("max_items", "20"))
    if fmt not in {"mp4", "webm", "mp3", "m4a"} or quality not in {"360", "480", "720", "1080", "1440", "2160", "best"}:
        raise ValueError("Unsupported output settings")
    if mode not in {"single", "collection"} or not 0 <= count <= 10000:
        raise ValueError("Invalid collection settings")
    if mode == "single" and (path == "/playlist" or re.match(r"/(channel|user|c)/|/@", path)):
        raise ValueError("Select collection mode for playlists and channels")
    query = {key: values[0] for key, values in params.items() if key in {"v", "list"}}
    normalized = urlunparse(("https", "www.youtube.com", quote(path, safe="/@-._~"), "", urlencode(query), ""))
    return {"job_id": job_id, "url": normalized, "format": fmt, "quality": quality,
            "mode": mode, "max_items": count,
            **{key: boolean(inputs.get(key, False)) for key in ("subtitles", "thumbnail", "metadata")}}


def validate_cookies(text):
    if len(text.encode("utf-8")) > 24000:
        raise ValueError("Cookie file is too large")
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#") and not line.startswith("#HttpOnly_"):
            continue
        row = line.removeprefix("#HttpOnly_").split("\t")
        if len(row) != 7:
            raise ValueError("Cookies must use Netscape format")
        domain = row[0].lstrip(".").lower()
        if domain != "youtube.com" and not domain.endswith(".youtube.com"):
            raise ValueError("Only YouTube cookies may be passed to this worker")
        rows.append(line)
    if not rows:
        raise ValueError("No YouTube cookies found")
    return "# Netscape HTTP Cookie File\n" + "\n".join(rows) + "\n"


def decrypt_cookies(envelope, private_pem, job_id):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(envelope) > 40000 or not private_pem:
        raise ValueError("Encrypted cookie payload or YT_COOKIE_PRIVATE_KEY is missing or invalid")
    try:
        data = json.loads(envelope)
        if data.get("v") != 1:
            raise ValueError()
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        raw_key = key.decrypt(base64.b64decode(data["ek"], validate=True), padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        plaintext = AESGCM(raw_key).decrypt(base64.b64decode(data["iv"], validate=True),
            base64.b64decode(data["ct"], validate=True), job_id.encode()).decode("utf-8")
        return validate_cookies(plaintext)
    except Exception as exc:
        raise ValueError("Could not decrypt YouTube cookies. Check the public/private key pair.") from exc


def download_options(cfg, output, cookiefile=None):
    bound = "" if cfg["quality"] == "best" else "[height<=" + cfg["quality"] + "]"
    postprocessors = []
    fmt = cfg["format"]
    if fmt in {"mp3", "m4a"}:
        format_spec = "bestaudio/best"
        postprocessors.append({"key": "FFmpegExtractAudio", "preferredcodec": fmt, "preferredquality": "192"})
    elif fmt == "mp4":
        format_spec = f"bv*[ext=mp4][vcodec^=avc1]{bound}+ba[ext=m4a]/b[ext=mp4]{bound}/bv*{bound}+ba/b{bound}"
        postprocessors.append({"key": "FFmpegVideoRemuxer", "preferedformat": "mp4"})
    else:
        format_spec = f"bv*[ext=webm]{bound}+ba[ext=webm]/b[ext=webm]{bound}/bv*{bound}+ba/b{bound}"
        postprocessors.append({"key": "FFmpegVideoRemuxer", "preferedformat": "webm"})
    if cfg["subtitles"]:
        postprocessors.append({"key": "FFmpegSubtitlesConvertor", "format": "srt"})
    opts = {"format": format_spec, "merge_output_format": fmt if fmt in {"mp4", "webm"} else None,
            "outtmpl": str(output / "media" / "%(autonumber)05d-%(title).90B [%(id)s].%(ext)s"),
            "noplaylist": cfg["mode"] == "single", "ignoreerrors": cfg["mode"] == "collection",
            "windowsfilenames": True, "restrictfilenames": False,
            "writethumbnail": cfg["thumbnail"], "writeinfojson": cfg["metadata"], "clean_infojson": True,
            "writesubtitles": cfg["subtitles"], "writeautomaticsub": cfg["subtitles"],
            "subtitleslangs": ["he", "en"], "subtitlesformat": "vtt/best",
            "postprocessors": postprocessors, "quiet": True, "no_warnings": True,
            "socket_timeout": 30, "retries": 3, "fragment_retries": 3,
            "concurrent_fragment_downloads": 3, "js_runtimes": {"node": {}},
            "max_filesize": 2 * 1024**3, "skip_unavailable_fragments": False,
            "cachedir": False}
    if cfg["mode"] == "collection" and cfg["max_items"]:
        opts["playlistend"] = cfg["max_items"]
    if cookiefile:
        opts["cookiefile"] = str(cookiefile)
    return opts


class SafeLogger:
    def __init__(self):
        self.errors = []
    def debug(self, message):
        pass
    def warning(self, message):
        pass
    def error(self, message):
        # Do not echo upstream URLs, credentials, headers or cookie contents.
        self.errors.append("An item could not be downloaded. The source may be unavailable or require updated cookies.")


def perform(inputs, output, downloader=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "downloaded_files": [], "errors": []}
    cookie_path = None
    try:
        cfg = validate(inputs)
        report.update({key: value for key, value in cfg.items()})
        encrypted = str(inputs.get("encrypted_cookies", ""))
        if encrypted:
            text = decrypt_cookies(encrypted, os.environ.get("YT_COOKIE_PRIVATE_KEY", ""), cfg["job_id"])
            temp = tempfile.NamedTemporaryFile(prefix="yt-cookies-", suffix=".txt", delete=False,
                dir=os.environ.get("RUNNER_TEMP") or None)
            cookie_path = Path(temp.name)
            try:
                os.chmod(cookie_path, 0o600)
                temp.write(text.encode("utf-8"))
            finally:
                temp.close()
            text = ""
        if downloader is None:
            from yt_dlp import YoutubeDL
            downloader = YoutubeDL
        logger = SafeLogger()
        opts = download_options(cfg, output, cookie_path)
        opts["logger"] = logger
        completed = set()
        def progress(event):
            if shutil.disk_usage(output).free < 1024**3:
                raise RuntimeError("Runner disk space is low. Download fewer items per batch.")
            if event.get("status") == "finished":
                completed.add(event.get("filename", ""))
                print(f"Finished media stream {len(completed)}", flush=True)
        opts["progress_hooks"] = [progress]
        with downloader(opts) as ydl:
            result = ydl.download([cfg["url"]])
        media_files = [p for p in (output / "media").rglob("*") if p.is_file()]
        report["downloaded_files"] = [{"path": str(p.relative_to(output)), "bytes": p.stat().st_size} for p in media_files]
        playable = [p for p in media_files if p.suffix.lower() in {".mp4", ".webm", ".mp3", ".m4a", ".mkv"}]
        report["errors"] = logger.errors[:30]
        if not playable:
            raise RuntimeError("No playable files were downloaded. YouTube may require fresh cookies or may block the runner.")
        report["status"] = "success" if result == 0 and not logger.errors else "partial"
        report["media_count"] = len(playable)
        return 0 if report["status"] == "success" else 1
    except (ValueError, RuntimeError) as exc:
        report["errors"].append(str(exc)[:800])
        return 1
    except Exception:
        report["errors"].append("The media service returned an error. Check the URL, output settings and YouTube access from the runner.")
        return 1
    finally:
        if cookie_path:
            cookie_path.unlink(missing_ok=True)
        # Preserve an accurate inventory even when a later item or conversion fails.
        if not report["downloaded_files"]:
            files = [p for p in (output / "media").rglob("*") if p.is_file()]
            report["downloaded_files"] = [{"path": str(p.relative_to(output)), "bytes": p.stat().st_size} for p in files]
            count = sum(p.suffix.lower() in {".mp4", ".webm", ".mp3", ".m4a", ".mkv"} for p in files)
            report["media_count"] = count
            if count and report["status"] == "failed":
                report["status"] = "partial"
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        (output / "READ-ME.txt").write_text(
            "YouTube Proxy result\n\nMedia files are in media/.\n"
            "report.json lists files, sizes and any errors.\n"
            "An empty media folder usually means YouTube blocked this runner or required fresh cookies.\n"
            "No cookie file or private key is included in this artifact.\n", encoding="utf-8")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(f"## YouTube Proxy\nStatus: {report['status']}\n\nMedia files: {report.get('media_count', 0)}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--output", default="output")
    args = parser.parse_args()
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    return perform(event.get("inputs", {}), args.output)


if __name__ == "__main__":
    sys.exit(main())

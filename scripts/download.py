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

WORKER_VERSION = "1.2.0"


def safe_diagnostic(message, secrets=()):
    """Keep the useful error while removing cookies, keys and signed URLs."""
    text = str(message)
    for secret in sorted({str(s) for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "[secret removed]")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                  "[private key removed]", text, flags=re.DOTALL)
    text = re.sub(r"(?im)^\s*(?:#HttpOnly_)?[^\s]+\t(?:TRUE|FALSE)\t[^\r\n]*",
                  "[cookie row removed]", text)
    text = re.sub(r"(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:[^\r\n]*",
                  "[sensitive header removed]", text)
    text = re.sub(r"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]+", "[token removed]", text)
    text = re.sub(r"(?i)https?://[^\s<>\"']+", "[URL removed]", text)
    text = re.sub(r"(?i)\b(?:access[_-]?token|api[_-]?key|client[_-]?secret|password|signature|sig)"
                  r"\s*[=:]\s*[^\s,;]+", "[credential removed]", text)
    return " ".join(text.split())[:1000]


def failure_hint(message):
    """A suggestion follows the reported error; it is not a guessed diagnosis."""
    lower = message.lower()
    if any(s in lower for s in ("sign in", "login required", "cookies are no longer valid", "confirm you're not a bot")):
        return "YouTube requested authentication. If you have access to this video, try fresh encrypted YouTube cookies. A runner IP block can still prevent access."
    if "requested format is not available" in lower or "no video formats" in lower:
        return "Try a different quality or output format. The requested video format was unavailable."
    if "429" in lower or "too many requests" in lower:
        return "YouTube is limiting requests. Wait before starting another download."
    if "403" in lower or "forbidden" in lower:
        return "YouTube refused access from this runner. Retrying or adding cookies does not guarantee access."
    if "private video" in lower or "video unavailable" in lower or "not available in your country" in lower:
        return "Check that the video is available and that your account is allowed to view it."
    if "ffmpeg" in lower and any(s in lower for s in ("not found", "not installed", "not available")):
        return "Check that the workflow installed FFmpeg successfully."
    if "certificate_verify_failed" in lower or "certificate verify failed" in lower:
        return "The runner could not verify the server certificate. Check its network and trusted certificates."
    return "Use the error details above to check the video, output settings or runner access."


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
    fmt = inputs.get("format", "mp3")
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
            "postprocessors": postprocessors, "quiet": True, "no_warnings": False,
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
    def __init__(self, secrets=()):
        self.errors = []
        self.warnings = []
        self.secrets = secrets
    def debug(self, message):
        pass
    def warning(self, message):
        self._remember(self.warnings, message, 10)
    def error(self, message):
        self._remember(self.errors, message, 30)
    def _remember(self, target, message, limit):
        value = safe_diagnostic(message, self.secrets)
        if value and value not in target and len(target) < limit:
            target.append(value)


def publish_media(output, cfg):
    """Publish complete files in the requested format and explicitly selected extras."""
    delivery = output / 'delivery'
    delivery.mkdir(parents=True, exist_ok=True)
    files = []
    for source in sorted((output / 'media').rglob('*')):
        if not source.is_file() or source.is_symlink() or source.stat().st_size == 0:
            continue
        suffix = source.suffix.lower()
        selected = suffix == '.' + cfg['format']
        selected |= cfg['subtitles'] and suffix in {'.srt', '.vtt', '.ass'}
        selected |= cfg['thumbnail'] and suffix in {'.jpg', '.jpeg', '.png', '.webp'}
        selected |= cfg['metadata'] and source.name.endswith('.info.json')
        if not selected:
            continue
        target = delivery / source.relative_to(output / 'media')
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(source, target)
        except OSError:
            shutil.copy2(source, target)
        files.append(target)
    return files


def perform(inputs, output, downloader=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "downloaded_files": [], "errors": [],
              "worker_version": WORKER_VERSION, "stage": "validate",
              "cookie_supplied": bool(str(inputs.get('encrypted_cookies', '')).strip()), "media_only_delivery": True}
    cookie_path = None
    logger = None
    cfg = None
    secrets = [str(inputs.get("encrypted_cookies", "")), os.environ.get("YT_COOKIE_PRIVATE_KEY", "")]
    print("YouTube Proxy worker " + WORKER_VERSION, flush=True)
    try:
        cfg = validate(inputs)
        report.update({key: value for key, value in cfg.items()})
        encrypted = str(inputs.get("encrypted_cookies", ""))
        if encrypted:
            report["stage"] = "decrypt_cookies"
            text = decrypt_cookies(encrypted, os.environ.get("YT_COOKIE_PRIVATE_KEY", ""), cfg["job_id"])
            secrets.extend(line.split("\t")[6] for line in text.splitlines()
                           if not line.startswith("#") and len(line.split("\t")) == 7)
            secrets.extend(line.removeprefix("#HttpOnly_").split("\t")[6] for line in text.splitlines()
                           if line.startswith("#HttpOnly_") and len(line.split("\t")) == 7)
            temp = tempfile.NamedTemporaryFile(prefix="yt-cookies-", suffix=".txt", delete=False,
                dir=os.environ.get("RUNNER_TEMP") or None)
            cookie_path = Path(temp.name)
            secrets.append(str(cookie_path))
            try:
                os.chmod(cookie_path, 0o600)
                temp.write(text.encode("utf-8"))
            finally:
                temp.close()
            text = ""
        report["stage"] = "initialize_downloader"
        if downloader is None:
            from yt_dlp import YoutubeDL
            downloader = YoutubeDL
        logger = SafeLogger(secrets)
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
            report["stage"] = "download"
            result = ydl.download([cfg["url"]])
        report["stage"] = "check_output"
        media_files = [p for p in (output / "media").rglob("*") if p.is_file()]
        report["downloaded_files"] = [{"path": str(p.relative_to(output)), "bytes": p.stat().st_size} for p in media_files]
        playable = [p for p in media_files if p.suffix.lower() == '.' + cfg['format'] and p.stat().st_size > 0]
        report["errors"] = logger.errors[:30]
        if not playable:
            raise RuntimeError("No playable files were downloaded in the requested format. Read the upstream error or conversion warning.")
        report["status"] = "success" if result == 0 and not logger.errors else "partial"
        report["media_count"] = len(playable)
        report["stage"] = "completed"
        return 0 if report["status"] == "success" else 1
    except Exception as exc:
        report["exception_type"] = type(exc).__name__
        report["errors"].append(safe_diagnostic(exc, secrets) or "The download failed without further error details.")
        return 1
    finally:
        if cookie_path:
            cookie_path.unlink(missing_ok=True)
        reported = (logger.errors if logger else []) + report["errors"]
        report["errors"] = list(dict.fromkeys(reported))[:30]
        report["warnings"] = logger.warnings if logger else []
        # Preserve an accurate inventory even when a later item or conversion fails.
        if not report["downloaded_files"]:
            files = [p for p in (output / "media").rglob("*") if p.is_file()]
            report["downloaded_files"] = [{"path": str(p.relative_to(output)), "bytes": p.stat().st_size} for p in files]
            count = sum(p.suffix.lower() == '.' + cfg['format'] and p.stat().st_size > 0 for p in files) if cfg else 0
            report["media_count"] = count
            if count and report["status"] == "failed":
                report["status"] = "partial"
        if report["errors"]:
            combined = " ".join(report["errors"])
            report['error_code'] = 'auth_required' if re.search(r'sign in|login required|cookies are no longer valid', combined, re.I) else 'download_failed'
            report["next_step"] = failure_hint(combined)
            if report['error_code'] == 'auth_required' and not report['cookie_supplied']:
                report['next_step'] = 'No YouTube cookies were sent with this request. Select your cookies file in the userscript and start a new request. ' + report['next_step']
            print("YouTube Proxy error details at stage: " + report["stage"], flush=True)
            if report.get("exception_type"):
                print("Exception: " + report["exception_type"], flush=True)
            for message in report["errors"][:5]:
                print("YouTube Proxy error: " + message, flush=True)
            print("Next step: " + report["next_step"], flush=True)
        for message in report["warnings"][:3]:
            print("YouTube Proxy warning: " + message, flush=True)
        delivery = publish_media(output, cfg) if cfg else []
        report['delivered_files'] = [{'path': str(p.relative_to(output / 'delivery')), 'bytes': p.stat().st_size} for p in delivery]
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        (output / "READ-ME.txt").write_text(
            "YouTube Proxy result\n\nMedia files are in media/.\n"
            "report.json lists files, sizes and any errors.\n"
            "If no media was downloaded, read the error details in report.json or the workflow log.\n"
            "No cookie file or private key is included in this artifact.\n", encoding="utf-8")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(f"## YouTube Proxy\nStatus: {report['status']}\n\nMedia files: {report.get('media_count', 0)}\n")
                if report["errors"]:
                    # A code block keeps upstream text from creating links or markup.
                    details = "\n".join(report["errors"][:5]).replace("`", "'")
                    f.write("\nError details:\n\n```text\n" + details + "\n```\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--output", default="output")
    args = parser.parse_args()
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    return perform(event.get("inputs", {}), args.output)


if __name__ == "__main__":
    sys.exit(main())

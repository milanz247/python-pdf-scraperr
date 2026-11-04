#!/usr/bin/env python3
"""Local PDF search engine for the clear web and Tor onion services.

The application manages its own private Tor runtime, searches public indexes,
validates PDF candidates without loading whole files into memory, and proxies
authorized result downloads to the browser. Use only for lawful, authorized
research and publicly accessible material.
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import ipaddress
import logging
import os
import platform
import queue
import random
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, Response, jsonify, render_template_string, request
from requests import Response as RequestsResponse
from requests import Session
from requests.exceptions import RequestException
from werkzeug.utils import secure_filename


APP_HOST = "127.0.0.1"
APP_PORT = 5000
TOR_PORT = 9050
MAX_RESULTS = 25
DEFAULT_RESULTS = 10
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
REQUEST_TIMEOUT = 30
TOR_BOOTSTRAP_TIMEOUT = 120
PDF_MAGIC = b"%PDF-"
AHMIA_ONION = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
AHMIA_CLEAR = "https://ahmia.fi"
DDG_HTML = "https://html.duckduckgo.com/html/"
DDG_LITE = "https://lite.duckduckgo.com/lite/"
ARCHIVE_SEARCH = "https://archive.org/advancedsearch.php"
ARCHIVE_METADATA = "https://archive.org/metadata/"
ARCHIVE_DOWNLOAD = "https://archive.org/download/"
TOR_CHECK = "https://check.torproject.org/api/ip"
TOR_DIST = "https://dist.torproject.org/torbrowser/"
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
)
SYSTEM_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("pdf-search")
app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=64 * 1024, JSON_SORT_KEYS=False)


def make_session(proxy: str | None = None) -> Session:
    session = requests.Session()
    session.trust_env = proxy is None
    session.headers.update({"Accept-Language": "en-US,en;q=0.8"})
    # Virtual environments normally make Requests use certifi. On managed Linux
    # networks, the locally trusted inspection/root CA is often present only in
    # the OS trust store. Prefer an explicit override, then that system bundle;
    # certificate verification always remains enabled.
    ca_bundle = os.environ.get("PDF_SEARCH_CA_BUNDLE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle:
        ca_path = Path(ca_bundle).expanduser()
        if not ca_path.is_file():
            raise RuntimeError(f"Configured CA bundle does not exist: {ca_path}")
        session.verify = str(ca_path)
    elif platform.system() == "Linux" and SYSTEM_CA_BUNDLE.is_file():
        session.verify = str(SYSTEM_CA_BUNDLE)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def http_request(session: Session, method: str, url: str, **kwargs: Any) -> RequestsResponse:
    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("User-Agent", random.choice(USER_AGENTS))
    return session.request(method, url, headers=headers, **kwargs)


def is_onion(url: str) -> bool:
    host = (urlparse(url).hostname or "").rstrip(".").lower()
    return host.endswith(".onion")


def safe_public_url(url: str) -> bool:
    """Reject non-HTTP and local/private clear-web destinations (SSRF guard)."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        return False
    host = parsed.hostname.rstrip(".").lower()
    if is_onion(url):
        return True
    if host in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443)}
    except (OSError, ValueError):
        return False
    if not addresses:
        return False
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            return False
    return True


class TorRuntime:
    """Install (when needed), bootstrap, verify, and own a private Tor process."""

    def __init__(self, root: Path, port: int = TOR_PORT) -> None:
        self.root = root.resolve()
        self.bin_dir = self.root / ".tor_bin"
        self.data_dir = self.root / ".tor_data"
        self.port = port
        self.process = None
        self.lock = threading.RLock()
        self.ready = False

    @staticmethod
    def platform_bundle() -> tuple[str, str]:
        system = platform.system().lower()
        machine = platform.machine().lower()
        os_tag = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(system)
        if not os_tag:
            raise RuntimeError(f"Unsupported operating system: {platform.system()}")
        if machine in {"amd64", "x86_64", "x64"}:
            arch = "x86_64"
        elif machine in {"arm64", "aarch64"} and os_tag in {"linux", "macos"}:
            arch = "aarch64"
        elif machine in {"x86", "i386", "i686"} and os_tag == "windows":
            arch = "i686"
        else:
            raise RuntimeError(f"No Tor Expert Bundle is available for {os_tag}/{machine}")
        return os_tag, arch

    def local_binary(self) -> Path | None:
        name = "tor.exe" if os.name == "nt" else "tor"
        if self.bin_dir.is_dir():
            matches = sorted(
                (path for path in self.bin_dir.rglob(name) if path.is_file()),
                key=lambda path: ("debug" in path.parts, len(path.parts), str(path)),
            )
            return matches[0].resolve() if matches else None
        return None

    def find_or_install(self) -> Path:
        installed = shutil.which("tor")
        if installed:
            LOG.info("Using Tor on PATH: %s", installed)
            return Path(installed).resolve()
        cached = self.local_binary()
        if cached:
            LOG.info("Using cached Tor: %s", cached)
            return cached
        return self.download_bundle()

    @staticmethod
    def stable_versions(html: str) -> list[str]:
        found = set(re.findall(r'href=["\'](\d+(?:\.\d+)+)/["\']', html))
        return sorted(found, key=lambda value: tuple(map(int, value.split("."))), reverse=True)

    def download_bundle(self) -> Path:
        os_tag, arch = self.platform_bundle()
        session = make_session()
        archive_path: Path | None = None
        try:
            LOG.info("Tor missing; finding the latest official Expert Bundle for %s/%s", os_tag, arch)
            index = http_request(session, "GET", TOR_DIST, timeout=30, allow_redirects=False)
            index.raise_for_status()
            choice: tuple[str, str, str] | None = None
            for version in self.stable_versions(index.text)[:10]:
                base = urljoin(TOR_DIST, f"{version}/")
                page = http_request(session, "GET", base, timeout=30, allow_redirects=False)
                if page.status_code != 200:
                    continue
                pattern = rf"tor-expert-bundle-{os_tag}-{arch}-{re.escape(version)}\.tar\.gz"
                match = re.search(pattern, page.text)
                if match:
                    choice = version, base, match.group(0)
                    break
            if not choice:
                raise RuntimeError(f"Official Tor bundle not found for {os_tag}/{arch}")
            version, base, filename = choice
            sums = http_request(
                session, "GET", urljoin(base, "sha256sums-unsigned-build.txt"),
                timeout=30, allow_redirects=False,
            )
            sums.raise_for_status()
            expected = next(
                (
                    line.split()[0].lower()
                    for line in sums.text.splitlines()
                    if len(line.split()) >= 2 and Path(line.split()[-1].lstrip("*")).name == filename
                ),
                None,
            )
            if not expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise RuntimeError("Official checksum manifest has no valid entry for the bundle")

            response = http_request(session, "GET", urljoin(base, filename), stream=True, timeout=60)
            response.raise_for_status()
            declared = parse_length(response.headers.get("Content-Length"))
            if declared and declared > 100 * 1024 * 1024:
                response.close()
                raise RuntimeError("Tor bundle unexpectedly exceeds 100 MiB")
            digest = hashlib.sha256()
            with tempfile.NamedTemporaryFile(prefix="tor-bundle-", suffix=".tar.gz", delete=False) as tmp:
                archive_path = Path(tmp.name)
                total = 0
                for chunk in response.iter_content(256 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > 100 * 1024 * 1024:
                        raise RuntimeError("Tor bundle exceeded the 100 MiB safety limit")
                    digest.update(chunk)
                    tmp.write(chunk)
            response.close()
            if digest.hexdigest().lower() != expected:
                raise RuntimeError("Tor Expert Bundle checksum verification failed")
            self.bin_dir.mkdir(parents=True, exist_ok=True)
            self.safe_extract(archive_path, self.bin_dir)
            binary = self.local_binary()
            if not binary:
                raise RuntimeError("Verified Tor bundle did not contain the Tor executable")
            if os.name != "nt":
                binary.chmod(binary.stat().st_mode | 0o111)
            elif os.name == "nt":
                with contextlib.suppress(Exception):
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(str(self.bin_dir), 0x02)
            LOG.info("Installed Tor Expert Bundle %s at %s", version, binary)
            return binary
        except (OSError, RequestException, tarfile.TarError) as exc:
            raise RuntimeError(f"Unable to install Tor automatically: {exc}") from exc
        finally:
            session.close()
            if archive_path:
                archive_path.unlink(missing_ok=True)

    @staticmethod
    def safe_extract(path: Path, destination: Path) -> None:
        root = destination.resolve()
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                target = (root / member.name).resolve()
                if target != root and root not in target.parents:
                    raise RuntimeError(f"Unsafe archive path: {member.name}")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise RuntimeError(f"Unsafe archive member: {member.name}")
            archive.extractall(root, members=members)

    def start(self, status: Callable[[str], None] | None = None) -> None:
        with self.lock:
            if self.ready and self.process and self.process.poll() is None:
                return
            binary = self.find_or_install()
            if port_in_use(self.port):
                raise RuntimeError(f"Port {self.port} is already in use; cannot safely own a private Tor runtime")
            self.data_dir.mkdir(parents=True, exist_ok=True)
            config: dict[str, str] = {
                "SocksPort": f"127.0.0.1:{self.port}",
                "DataDirectory": str(self.data_dir),
                "ClientOnly": "1",
                "AvoidDiskWrites": "1",
                "Log": "NOTICE stdout",
            }
            if self.bin_dir.resolve() in binary.parents:
                for filename, setting in (("geoip", "GeoIPFile"), ("geoip6", "GeoIPv6File")):
                    found = next((p for p in self.bin_dir.rglob(filename) if p.is_file()), None)
                    if found:
                        config[setting] = str(found.resolve())

            last = -1
            def on_line(line: str) -> None:
                nonlocal last
                match = re.search(r"Bootstrapped (\d+)%", line)
                if match:
                    percent = int(match.group(1))
                    if percent != last:
                        last = percent
                        LOG.info("Tor bootstrap: %s%%", percent)
                        if status:
                            status(f"Connecting to Tor… {percent}%")

            LOG.info("Launching private Tor runtime on 127.0.0.1:%s", self.port)
            try:
                self.process = self._launch_with_timeout(binary, config, on_line)
            except OSError as exc:
                raise RuntimeError(f"Tor failed to bootstrap: {exc}") from exc
            self.verify()
            self.ready = True
            LOG.info("Tor bootstrap reached 100%% and routing was verified")

    def _launch_with_timeout(
        self, binary: Path, config: dict[str, str], on_line: Callable[[str], None]
    ) -> subprocess.Popen[str]:
        """Launch Tor with a thread-safe deadline and streamed bootstrap logs.

        Stem's timeout uses SIGALRM and therefore cannot operate in Flask's
        worker thread. This uses the same Tor ownership option as Stem while
        applying a monotonic deadline that works on every supported OS.
        """
        command = [str(binary)]
        for key, value in config.items():
            command.extend((f"--{key}", value))
        command.extend(("__OwningControllerProcess", str(os.getpid())))
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        environment = os.environ.copy()
        if platform.system() == "Linux" and self.bin_dir.resolve() in binary.parents:
            library_dir = str(binary.parent)
            existing_library_path = environment.get("LD_LIBRARY_PATH")
            environment["LD_LIBRARY_PATH"] = os.pathsep.join(
                part for part in (library_dir, existing_library_path) if part
            )
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
            env=environment,
        )
        self.process = process
        lines: queue.Queue[str | None] = queue.Queue()

        def read_output() -> None:
            assert process.stdout is not None
            try:
                for line in process.stdout:
                    lines.put(line.rstrip())
            finally:
                lines.put(None)

        threading.Thread(target=read_output, name="tor-output", daemon=True).start()
        deadline = time.monotonic() + TOR_BOOTSTRAP_TIMEOUT
        last_problem = "Tor could not connect to its relay network"
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=min(1.0, max(0.05, deadline - time.monotonic())))
            except queue.Empty:
                if process.poll() is not None:
                    break
                continue
            if line is None:
                break
            on_line(line)
            problem = re.search(r"\[(warn|err)\]\s+(.*)$", line, re.IGNORECASE)
            if problem and "see warnings above" not in problem.group(2).lower():
                last_problem = problem.group(2).strip()
                LOG.warning("Tor: %s", last_problem)
            bootstrapped = re.search(r"Bootstrapped (\d+)%", line)
            if bootstrapped and int(bootstrapped.group(1)) >= 100:
                return process

        self.stop()
        if process.poll() is not None and last_problem == "Tor could not connect to its relay network":
            last_problem = f"Tor exited with status {process.returncode}"
        raise OSError(
            f"bootstrap did not reach 100% within {TOR_BOOTSTRAP_TIMEOUT}s: {last_problem}. "
            "Your network may block direct Tor relays and require a bridge."
        )

    def verify(self) -> None:
        session = self.session()
        try:
            response = http_request(session, "GET", TOR_CHECK, timeout=30, allow_redirects=False)
            response.raise_for_status()
            if not response.json().get("IsTor", False):
                raise RuntimeError("Tor Project did not recognize the private runtime's exit address")
        except (RequestException, ValueError) as exc:
            raise RuntimeError(f"Unable to verify Tor routing: {exc}") from exc
        finally:
            session.close()

    def session(self) -> Session:
        return make_session(f"socks5h://127.0.0.1:{self.port}")

    def stop(self) -> None:
        with self.lock:
            process, self.process = self.process, None
            self.ready = False
            if process is None or process.poll() is not None:
                return
            LOG.info("Stopping private Tor runtime")
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:
                process.kill()
                with contextlib.suppress(Exception):
                    process.wait(timeout=5)


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def parse_length(value: str | None) -> int | None:
    try:
        number = int(value or "")
        return number if number >= 0 else None
    except ValueError:
        return None


TOR = TorRuntime(Path(__file__).resolve().parent)
atexit.register(TOR.stop)
EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="pdf-search")


@dataclass
class SearchJob:
    query: str
    limit: int
    state: str = "queued"
    message: str = "Preparing search…"
    results: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    updated: float = field(default_factory=time.time)


JOBS: dict[str, SearchJob] = {}
JOBS_LOCK = threading.RLock()
DOWNLOADS: dict[str, tuple[str, int, float]] = {}
DOWNLOADS_LOCK = threading.RLock()


def update_job(job_id: str, message: str, state: str | None = None) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        job.message = message
        job.updated = time.time()
        if state:
            job.state = state


def cleanup_state() -> None:
    cutoff = time.time() - 3600
    with JOBS_LOCK:
        for key in [key for key, job in JOBS.items() if job.updated < cutoff]:
            JOBS.pop(key, None)
    with DOWNLOADS_LOCK:
        for key in [key for key, value in DOWNLOADS.items() if value[2] < cutoff]:
            DOWNLOADS.pop(key, None)


def unwrap_url(href: str, base: str) -> str | None:
    absolute = urljoin(base, href)
    parsed = urlparse(absolute)
    values = parse_qs(parsed.query)
    for key in ("uddg", "redirect_url", "url"):
        if values.get(key):
            candidate = unquote(values[key][0])
            return candidate if safe_public_url(candidate) else None
    return absolute if safe_public_url(absolute) else None


def result_links(html: bytes | str, base: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    output: list[tuple[str, str]] = []
    seen: set[str] = set()
    for anchor in soup.select("a[href]"):
        url = unwrap_url(str(anchor.get("href")), base)
        if not url:
            continue
        url = url.split("#", 1)[0]
        if url in seen:
            continue
        seen.add(url)
        title = " ".join(anchor.get_text(" ", strip=True).split())
        output.append((url, title))
    return output


def routed_get(url: str, clear: Session, tor: Session, **kwargs: Any) -> RequestsResponse:
    """Follow redirects manually and re-evaluate routing/security on each hop."""
    current = url
    for _ in range(6):
        if not safe_public_url(current):
            raise RequestException("Blocked unsafe or non-public destination")
        session = tor if is_onion(current) else clear
        response = http_request(
            session, "GET", current, allow_redirects=False, timeout=REQUEST_TIMEOUT, **kwargs
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise RequestException("Redirect omitted its destination")
            current = urljoin(current, location)
            continue
        return response
    raise RequestException("Too many redirects")


def search_clearweb(query: str, clear: Session, limit: int) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for dork in (f'{query} filetype:pdf', f'{query} intitle:"index of" pdf'):
        for endpoint in (DDG_HTML, DDG_LITE):
            response = http_request(
                clear, "GET", endpoint, params={"q": dork}, timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if response.status_code != 200:
                LOG.warning(
                    "Clear-web search endpoint returned HTTP %s: %s",
                    response.status_code,
                    endpoint,
                )
                continue
            links = result_links(response.text, response.url)
            if links:
                found.extend(links)
                break
        if len(found) >= limit * 3:
            break
    return deduplicate(found)[: limit * 3]


def search_public_archive(query: str, clear: Session, limit: int) -> list[tuple[str, str]]:
    """Find directly downloadable, unrestricted PDFs in Internet Archive."""
    escaped = query.replace("\\", "\\\\").replace('"', '\\"')
    response = http_request(
        clear,
        "GET",
        ARCHIVE_SEARCH,
        params={
            "q": f'title:("{escaped}") AND mediatype:texts',
            "fl[]": ("identifier", "title"),
            "rows": min(10, max(1, limit)),
            "output": "json",
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )
    response.raise_for_status()
    try:
        documents = response.json().get("response", {}).get("docs", [])
    except (TypeError, ValueError) as exc:
        raise RequestException(f"Public archive returned invalid JSON: {exc}") from exc

    found: list[tuple[str, str]] = []
    for document in documents:
        identifier = str(document.get("identifier", "")).strip()
        title = " ".join(str(document.get("title", "")).split())
        if not identifier or not title or match_score(query, "", title) == 0:
            continue
        metadata_response = http_request(
            clear,
            "GET",
            f"{ARCHIVE_METADATA}{quote(identifier, safe='')}",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        metadata_response.raise_for_status()
        try:
            payload = metadata_response.json()
        except ValueError as exc:
            raise RequestException(f"Public archive metadata was invalid: {exc}") from exc
        restricted = str(payload.get("metadata", {}).get("access-restricted-item", "")).lower()
        if restricted in {"1", "true", "yes"}:
            continue
        files = sorted(
            payload.get("files", []),
            key=lambda item: (str(item.get("source", "")).lower() != "original", str(item.get("name", ""))),
        )
        for item in files:
            name = str(item.get("name", "")).strip()
            private = str(item.get("private", "")).lower()
            if not name.lower().endswith(".pdf") or private in {"1", "true", "yes"}:
                continue
            url = f"{ARCHIVE_DOWNLOAD}{quote(identifier, safe='')}/{quote(name, safe='/')}"
            found.append((url, title))
            break
        if len(found) >= limit:
            break
    return found


def search_darkweb(query: str, clear: Session, tor: Session, limit: int) -> list[tuple[str, str]]:
    errors: list[str] = []
    for base, session in ((AHMIA_ONION, tor), (AHMIA_CLEAR, tor)):
        try:
            response = http_request(
                session, "GET", f"{base}/search/", params={"q": f"{query} filetype:pdf"},
                timeout=REQUEST_TIMEOUT, allow_redirects=False,
            )
            response.raise_for_status()
            own_host = urlparse(base).hostname
            links = [item for item in result_links(response.text, response.url)
                     if urlparse(item[0]).hostname != own_host]
            if links:
                return deduplicate(links)[: limit * 4]
        except RequestException as exc:
            errors.append(str(exc))
    if errors:
        LOG.warning("Ahmia search endpoints failed: %s", "; ".join(errors))
    return []


def deduplicate(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    output: list[tuple[str, str]] = []
    seen: set[str] = set()
    for url, title in items:
        if url not in seen:
            seen.add(url)
            output.append((url, title))
    return output


def display_name(url: str, supplied: str = "") -> str:
    candidate = unquote(Path(urlparse(url).path).name)
    if not candidate.lower().endswith(".pdf"):
        candidate = supplied or candidate or "PDF document"
    candidate = re.sub(r"[\x00-\x1f<>:\"/\\|?*]+", " ", candidate)
    return " ".join(candidate.split())[:180] or "PDF document"


def normalized_document_name(value: str) -> str:
    """Normalize a query/title/filename for conservative exact matching."""
    value = unquote(value).lower().strip()
    value = re.sub(r"\.pdf(?:\s|$)", " ", value)
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def match_score(query: str, url: str, title: str) -> int:
    """Prefer an exact filename, then a clearly matching search-result title."""
    wanted = normalized_document_name(query)
    if not wanted:
        return 0
    filename = normalized_document_name(Path(urlparse(url).path).name)
    heading = normalized_document_name(title)
    if wanted == filename:
        return 4
    if wanted == heading:
        return 3
    # Search engines commonly append a site name or words such as "download"
    # to an otherwise exact title. Require the complete query as one phrase.
    padded_wanted = f" {wanted} "
    if padded_wanted in f" {filename} ":
        return 2
    if padded_wanted in f" {heading} ":
        return 2
    return 0


def human_size(size: int | None) -> str:
    if size is None:
        return "Size unknown"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return "Size unknown"


def validate_pdf(
    url: str, title: str, clear: Session, tor: Session, max_bytes: int
) -> dict[str, Any] | None:
    response: RequestsResponse | None = None
    try:
        response = routed_get(
            url, clear, tor, stream=True, headers={"Range": "bytes=0-4095", "Accept": "application/pdf,*/*;q=0.5"}
        )
        response.raise_for_status()
        size = parse_length(response.headers.get("Content-Range", "").rsplit("/", 1)[-1])
        if size is None:
            size = parse_length(response.headers.get("Content-Length"))
        if size is not None and size > max_bytes:
            return None
        first = next(response.iter_content(4096), b"")
        if not first.startswith(PDF_MAGIC):
            return None
        final_url = response.url
        token = secrets.token_urlsafe(24)
        with DOWNLOADS_LOCK:
            DOWNLOADS[token] = (final_url, max_bytes, time.time())
        source = "Dark Web .onion" if is_onion(final_url) or is_onion(url) else "Clearnet"
        return {
            "title": display_name(final_url, title),
            "url": final_url,
            "source": source,
            "size": human_size(size),
            "download": f"/download?url={quote(final_url, safe='')}&token={quote(token)}",
        }
    except RequestException:
        return None
    finally:
        if response is not None:
            response.close()


def run_search(job_id: str, max_bytes: int) -> None:
    clear = make_session()
    tor: Session | None = None
    try:
        job = JOBS[job_id]
        update_job(job_id, "Searching clear-web indexes…", "running")
        clear_candidates: list[tuple[str, str]] = []
        try:
            clear_candidates.extend(search_clearweb(job.query, clear, 10))
        except RequestException as exc:
            LOG.warning("Clear-web search failed: %s", exc)
        update_job(job_id, "Searching public PDF archives…")
        try:
            clear_candidates.extend(search_public_archive(job.query, clear, 10))
        except RequestException as exc:
            LOG.warning("Public archive search failed: %s", exc)

        def ranked(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
            return sorted(
                (item for item in deduplicate(items) if match_score(job.query, item[0], item[1]) > 0),
                key=lambda item: match_score(job.query, item[0], item[1]),
                reverse=True,
            )

        # Check clear-web exact matches first. A blocked Tor network should not
        # prevent a valid clear-web result from being returned immediately.
        placeholder_tor = make_session(f"socks5h://127.0.0.1:{TOR_PORT}")
        try:
            candidates = [item for item in ranked(clear_candidates) if not is_onion(item[0])]
            for index, (url, title) in enumerate(candidates, start=1):
                update_job(job_id, f"Verifying clear-web exact match {index} of {len(candidates)}…")
                result = validate_pdf(url, title, clear, placeholder_tor, max_bytes)
                if result:
                    with JOBS_LOCK:
                        JOBS[job_id].results = [result]
                    update_job(job_id, "Found the verified exact match", "complete")
                    return
        finally:
            placeholder_tor.close()

        update_job(job_id, "Connecting to Tor…")
        TOR.start(lambda message: update_job(job_id, message))
        tor = TOR.session()
        update_job(job_id, "Scanning Dark Web .onion directories…")
        candidates = ranked(search_darkweb(job.query, clear, tor, 10))
        update_job(job_id, f"Checking {len(candidates)} exact-match candidates…")
        verified: list[dict[str, Any]] = []
        for index, (url, title) in enumerate(candidates, start=1):
            update_job(job_id, f"Verifying exact match {index} of {len(candidates)}…")
            result = validate_pdf(url, title, clear, tor, max_bytes)
            if result:
                verified.append(result)
                with JOBS_LOCK:
                    JOBS[job_id].results = list(verified)
                # The requested exact PDF is verified; stop all further search
                # and validation work immediately.
                break
        message = "Found the verified exact match" if verified else "No verified exact match found"
        update_job(job_id, message, "complete")
    except Exception as exc:
        LOG.exception("Search job failed")
        with JOBS_LOCK:
            JOBS[job_id].error = str(exc)
        update_job(job_id, "Search failed", "error")
    finally:
        clear.close()
        if tor:
            tor.close()


INDEX_HTML = r"""
<!doctype html>
<html lang="en" class="h-full dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Local clear-web and Tor PDF search engine">
  <title>Lumen PDF Search</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config={darkMode:'class',theme:{extend:{fontFamily:{sans:['Inter','ui-sans-serif','system-ui']},colors:{ink:'#090b12',violet:'#8b5cf6'}}}}
  </script>
  <style>
    body{background-image:radial-gradient(circle at 50% -20%,rgba(99,102,241,.22),transparent 38%),radial-gradient(circle at 90% 20%,rgba(168,85,247,.12),transparent 24%)}
    .glass{background:rgba(15,18,29,.72);backdrop-filter:blur(22px);border:1px solid rgba(255,255,255,.08)}
    .shine{position:relative;overflow:hidden}.shine:after{content:"";position:absolute;inset:-100%;background:linear-gradient(110deg,transparent 40%,rgba(255,255,255,.08),transparent 60%);animation:shine 2.2s infinite}
    @keyframes shine{to{transform:translateX(50%)}} @media(prefers-reduced-motion:reduce){.shine:after{animation:none}}
  </style>
</head>
<body class="min-h-full bg-ink text-slate-100 antialiased selection:bg-violet/40">
  <main class="mx-auto min-h-screen max-w-5xl px-4 py-8 sm:px-6 sm:py-14">
    <header class="mb-14 flex items-center justify-between">
      <a href="/" class="flex items-center gap-3" aria-label="Lumen home">
        <span class="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-indigo-500 to-fuchsia-500 shadow-lg shadow-violet-950/50">
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9l-6-6H7a2 2 0 00-2 2v14a2 2 0 002 2z"/><path stroke-linecap="round" stroke-width="2" d="M13 3v6h6M8 14h8M8 17h5"/></svg>
        </span>
        <span><strong class="block tracking-tight">Lumen</strong><small class="text-xs text-slate-500">PDF intelligence search</small></span>
      </a>
      <span class="flex items-center gap-2 rounded-full border border-emerald-400/15 bg-emerald-400/5 px-3 py-1.5 text-xs text-emerald-300"><i class="h-1.5 w-1.5 rounded-full bg-emerald-400"></i>Runs locally</span>
    </header>

    <section class="mx-auto max-w-3xl text-center">
      <p class="mb-4 text-xs font-semibold uppercase tracking-[.28em] text-indigo-300">Clear web + Tor discovery</p>
      <h1 class="text-balance text-4xl font-semibold tracking-[-.04em] sm:text-6xl">Find the document<br><span class="bg-gradient-to-r from-indigo-300 via-violet-300 to-fuchsia-300 bg-clip-text text-transparent">others overlook.</span></h1>
      <p class="mx-auto mt-5 max-w-xl text-sm leading-6 text-slate-400 sm:text-base">Search indexed PDFs, open directories, and publicly discoverable onion repositories from one private workspace.</p>
      <form id="searchForm" class="glass mt-10 flex items-center gap-2 rounded-2xl p-2 shadow-2xl shadow-black/30 focus-within:border-indigo-400/40">
        <svg class="ml-3 h-5 w-5 shrink-0 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7" stroke-width="2"/><path d="m20 20-4-4" stroke-width="2" stroke-linecap="round"/></svg>
        <label class="sr-only" for="query">PDF name or topic</label>
        <input id="query" required maxlength="200" autocomplete="off" placeholder="Search a PDF name or topic…" class="min-w-0 flex-1 bg-transparent px-2 py-3 text-base outline-none placeholder:text-slate-600">
        <button id="submitButton" class="rounded-xl bg-white px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-indigo-100 disabled:cursor-wait disabled:opacity-60">Search</button>
      </form>
      <div class="mt-4 flex justify-center gap-5 text-xs text-slate-600"><span>Magic-byte verified</span><span>•</span><span>Tor isolated</span><span>•</span><span>50 MB limit</span></div>
    </section>

    <section id="statusPanel" class="mx-auto mt-12 hidden max-w-3xl" aria-live="polite">
      <div class="glass shine flex items-center gap-4 rounded-2xl p-5">
        <svg class="h-6 w-6 animate-spin text-indigo-400" fill="none" viewBox="0 0 24 24"><circle class="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8V0A12 12 0 000 12h4z"/></svg>
        <div><p id="statusText" class="text-sm font-medium">Preparing search…</p><p class="mt-1 text-xs text-slate-500">Onion services may take a little longer to respond.</p></div>
      </div>
    </section>

    <section id="resultsSection" class="mx-auto mt-14 hidden max-w-3xl">
      <div class="mb-5 flex items-end justify-between"><div><p class="text-xs uppercase tracking-[.2em] text-slate-500">Verified documents</p><h2 id="resultHeading" class="mt-1 text-xl font-semibold">Search results</h2></div><span id="resultCount" class="text-sm text-slate-500"></span></div>
      <div id="results" class="space-y-3"></div>
    </section>
  </main>
  <script>
    const form=document.querySelector('#searchForm'), query=document.querySelector('#query'), button=document.querySelector('#submitButton');
    const panel=document.querySelector('#statusPanel'), statusText=document.querySelector('#statusText'), section=document.querySelector('#resultsSection'), list=document.querySelector('#results'), count=document.querySelector('#resultCount');
    const escapeHtml=s=>String(s).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
    function card(item){const dark=item.source.includes('Dark');const badge=dark?'border-fuchsia-400/20 bg-fuchsia-400/10 text-fuchsia-300':'border-sky-400/20 bg-sky-400/10 text-sky-300';return `<article class="glass group rounded-2xl p-5 transition hover:-translate-y-0.5 hover:border-white/15"><div class="flex flex-col gap-4 sm:flex-row sm:items-center"><span class="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-red-400/10 text-xs font-bold text-red-300">PDF</span><div class="min-w-0 flex-1"><h3 class="truncate font-medium text-slate-100" title="${escapeHtml(item.title)}">${escapeHtml(item.title)}</h3><p class="mt-1 truncate text-xs text-slate-600">${escapeHtml(item.url)}</p><div class="mt-3 flex items-center gap-2"><span class="rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider ${badge}">${escapeHtml(item.source)}</span><span class="text-xs text-slate-500">${escapeHtml(item.size)}</span></div></div><a href="${escapeHtml(item.download)}" class="shrink-0 rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-center text-sm font-medium transition hover:border-indigo-400/30 hover:bg-indigo-400/10 hover:text-indigo-200">Download PDF</a></div></article>`}
    async function poll(id){for(;;){await new Promise(r=>setTimeout(r,900));const response=await fetch(`/api/search/${encodeURIComponent(id)}`,{cache:'no-store'});const data=await response.json();if(!response.ok)throw new Error(data.error||'Status request failed');statusText.textContent=data.message;if(data.results?.length){section.classList.remove('hidden');list.innerHTML=data.results.map(card).join('');count.textContent=`${data.results.length} found`;}if(data.state==='complete'){panel.classList.add('hidden');section.classList.remove('hidden');count.textContent=`${data.results.length} verified`;if(!data.results.length)list.innerHTML='<div class="glass rounded-2xl p-8 text-center text-sm text-slate-400">No verified PDFs were found. Try a more specific document title.</div>';return}if(data.state==='error')throw new Error(data.error||'Search failed')}}
    form.addEventListener('submit',async e=>{e.preventDefault();button.disabled=true;panel.classList.remove('hidden');section.classList.add('hidden');list.innerHTML='';statusText.textContent='Preparing exact-match search…';try{const response=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:query.value,limit:1,max_size_mb:50})});const data=await response.json();if(!response.ok)throw new Error(data.error||'Unable to start search');await poll(data.job_id)}catch(error){panel.classList.remove('hidden');panel.classList.remove('shine');statusText.textContent=error.message}finally{button.disabled=false}});
  </script>
</body>
</html>
"""


@app.after_request
def security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index() -> str:
    return render_template_string(INDEX_HTML)


@app.post("/api/search")
def create_search() -> tuple[Response, int] | Response:
    cleanup_state()
    data = request.get_json(silent=True) or {}
    query = " ".join(str(data.get("query", "")).split())
    if not query or len(query) > 200:
        return jsonify(error="Enter a query between 1 and 200 characters"), 400
    try:
        # This interface intentionally returns only the first verified exact
        # match, regardless of any legacy/client-provided result limit.
        limit = 1
        max_mb = min(500, max(1, int(data.get("max_size_mb", 50))))
    except (TypeError, ValueError):
        return jsonify(error="Invalid search limit"), 400
    job_id = secrets.token_urlsafe(18)
    with JOBS_LOCK:
        JOBS[job_id] = SearchJob(query=query, limit=limit)
    EXECUTOR.submit(run_search, job_id, max_mb * 1024 * 1024)
    return jsonify(job_id=job_id), 202


@app.get("/api/search/<job_id>")
def search_status(job_id: str) -> tuple[Response, int] | Response:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify(error="Search job not found or expired"), 404
        return jsonify(
            state=job.state, message=job.message, results=job.results, error=job.error
        )


@app.get("/download")
def download() -> Response | tuple[Response, int]:
    url = request.args.get("url", "")
    token = request.args.get("token", "")
    with DOWNLOADS_LOCK:
        authorization = DOWNLOADS.get(token)
    if not authorization or not secrets.compare_digest(authorization[0], url):
        return jsonify(error="This download URL was not issued by a verified search result"), 403
    if time.time() - authorization[2] > 3600 or not safe_public_url(url):
        return jsonify(error="Download authorization expired"), 410
    max_bytes = authorization[1]
    clear = make_session()
    tor = TOR.session()
    try:
        upstream = routed_get(url, clear, tor, stream=True, headers={"Accept": "application/pdf"})
        upstream.raise_for_status()
        declared = parse_length(upstream.headers.get("Content-Length"))
        if declared is not None and declared > max_bytes:
            upstream.close(); clear.close(); tor.close()
            return jsonify(error="PDF exceeds the configured size limit"), 413
        iterator = upstream.iter_content(128 * 1024)
        first = next(iterator, b"")
        if not first.startswith(PDF_MAGIC):
            upstream.close(); clear.close(); tor.close()
            return jsonify(error="Remote content is no longer a valid PDF"), 415
        filename = secure_filename(display_name(upstream.url)) or "document.pdf"
        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"
        filename = filename.replace('"', "_")

        def generate() -> Iterator[bytes]:
            total = 0
            try:
                for chunk in (first,):
                    total += len(chunk)
                    yield chunk
                for chunk in iterator:
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        LOG.warning("Upstream PDF crossed size limit during streaming: %s", url)
                        return
                    yield chunk
            finally:
                upstream.close()
                clear.close()
                tor.close()

        return Response(
            generate(), mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            direct_passthrough=True,
        )
    except RequestException as exc:
        clear.close(); tor.close()
        return jsonify(error=f"Download failed: {exc}"), 502


def open_browser() -> None:
    url = f"http://{APP_HOST}:{APP_PORT}"
    is_wsl = bool(os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"))
    has_desktop = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if platform.system() == "Linux" and (is_wsl or not has_desktop):
        LOG.info("No Linux desktop browser detected; open %s in your browser", url)
        return
    if not webbrowser.open(url, new=2):
        LOG.info("Could not open a browser automatically; open %s manually", url)


def main() -> None:
    # Bind the UI immediately. Tor bootstraps in the background on the first
    # search, allowing the browser to show live connection progress or a useful
    # error instead of receiving a refused connection during bootstrap.
    LOG.info("Starting web interface; Tor will bootstrap on the first search")
    timer = threading.Timer(1.0, open_browser)
    timer.daemon = True
    timer.start()
    try:
        app.run(host=APP_HOST, port=APP_PORT, debug=False, threaded=True, use_reloader=False)
    finally:
        EXECUTOR.shutdown(wait=False, cancel_futures=True)
        TOR.stop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except RuntimeError as exc:
        LOG.error("Startup failed: %s", exc)
        raise SystemExit(1)

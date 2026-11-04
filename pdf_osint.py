#!/usr/bin/env python3
"""Search for and download PDFs from the clear web and Tor onion services.

Use this tool only for sources and material you are legally authorized to access.
It does not bypass authentication, paywalls, robots, or access controls.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import hashlib
import itertools
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests import Response, Session
from requests.exceptions import RequestException, SSLError
from tqdm import tqdm
from stem.process import launch_tor_with_config


AHMIA_ONION = "http://juhanurmih5wuprs4fazzd2uv5phvdicnnst4x4tfdgahdit2h3vdyd.onion"
AHMIA_CLEAR = "https://ahmia.fi"
DDG_HTML = "https://html.duckduckgo.com/html/"
TOR_CHECK = "https://check.torproject.org/api/ip"
TOR_DIST = "https://dist.torproject.org/torbrowser/"
PDF_MAGIC = b"%PDF-"
HTML_INSPECTION_LIMIT = 2 * 1024 * 1024

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
)

LOG = logging.getLogger("pdf-osint")


@dataclass(frozen=True)
class Config:
    query: str
    limit: int
    output_dir: Path
    timeout: float
    max_bytes: int
    use_clearnet: bool
    use_darkweb: bool
    all_through_tor: bool


class ManagedTor:
    """Find/install, launch, and reliably stop a private Tor process."""

    def __init__(self, base_dir: Path, bootstrap_timeout: int = 180) -> None:
        self.base_dir = base_dir.resolve()
        self.bin_dir = self.base_dir / ".tor_bin"
        self.data_dir = self.base_dir / ".tor_data"
        self.bootstrap_timeout = bootstrap_timeout
        self.process = None
        self.port = 0
        self._atexit_registered = False

    @staticmethod
    def _platform_tag() -> tuple[str, str]:
        system = platform.system().lower()
        machine = platform.machine().lower()
        os_tag = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(system)
        if not os_tag:
            raise RuntimeError(f"Automatic Tor runtime is unsupported on {platform.system()}")
        if machine in {"amd64", "x86_64", "x64"}:
            arch = "x86_64"
        elif machine in {"arm64", "aarch64"}:
            arch = "aarch64"
        elif machine in {"x86", "i386", "i686"} and os_tag == "windows":
            arch = "i686"
        else:
            raise RuntimeError(f"No official Tor Expert Bundle for {os_tag}/{machine}")
        return os_tag, arch

    def _local_binary(self) -> Path | None:
        names = ("tor.exe",) if os.name == "nt" else ("tor",)
        if self.bin_dir.is_dir():
            for name in names:
                candidates = sorted(self.bin_dir.rglob(name), key=lambda p: len(p.parts))
                for candidate in candidates:
                    if candidate.is_file():
                        return candidate.resolve()
        return None

    def locate_or_install(self) -> Path:
        installed = shutil.which("tor")
        if installed:
            LOG.info("Using Tor from PATH: %s", installed)
            return Path(installed).resolve()
        local = self._local_binary()
        if local:
            LOG.info("Using cached Tor Expert Bundle: %s", local)
            return local
        return self._download_expert_bundle()

    @staticmethod
    def _stable_versions(index_html: str) -> list[str]:
        versions = set(re.findall(r'href=["\'](\d+(?:\.\d+)+)/["\']', index_html))
        return sorted(versions, key=lambda v: tuple(int(n) for n in v.split(".")), reverse=True)

    def _download_expert_bundle(self) -> Path:
        os_tag, arch = self._platform_tag()
        LOG.info("Tor not found; locating the latest official %s/%s Expert Bundle", os_tag, arch)
        bootstrap = make_session()
        try:
            index = request(bootstrap, "GET", TOR_DIST, timeout=30, allow_redirects=False)
            index.raise_for_status()
            versions = self._stable_versions(index.text)
            if not versions:
                raise RuntimeError("Tor distribution index contained no stable releases")

            selected: tuple[str, str, str] | None = None
            for version in versions[:8]:
                release_url = urljoin(TOR_DIST, f"{version}/")
                page = request(bootstrap, "GET", release_url, timeout=30, allow_redirects=False)
                if page.status_code != 200:
                    continue
                pattern = rf"tor-expert-bundle-{re.escape(os_tag)}-{re.escape(arch)}-{re.escape(version)}\.tar\.gz"
                match = re.search(pattern, page.text)
                if match:
                    selected = version, release_url, match.group(0)
                    break
            if selected is None:
                raise RuntimeError(f"No stable Tor Expert Bundle found for {os_tag}/{arch}")
            version, release_url, filename = selected
            checksum_url = urljoin(release_url, "sha256sums-unsigned-build.txt")
            sums = request(bootstrap, "GET", checksum_url, timeout=30, allow_redirects=False)
            sums.raise_for_status()
            expected = None
            for line in sums.text.splitlines():
                fields = line.strip().split()
                if len(fields) >= 2 and Path(fields[-1].lstrip("*")).name == filename:
                    expected = fields[0].lower()
                    break
            if not expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise RuntimeError(f"No valid SHA-256 entry published for {filename}")

            archive_url = urljoin(release_url, filename)
            LOG.info("Downloading official Tor Expert Bundle %s", version)
            with tempfile.NamedTemporaryFile(prefix="tor-expert-", suffix=".tar.gz", delete=False) as tmp:
                archive_path = Path(tmp.name)
                digest = hashlib.sha256()
                response = request(bootstrap, "GET", archive_url, stream=True, timeout=60)
                response.raise_for_status()
                declared = content_length(response)
                if declared and declared > 100 * 1024 * 1024:
                    raise RuntimeError("Tor bundle unexpectedly exceeds 100 MiB")
                with response, tqdm(
                    total=declared, desc="Downloading Tor", unit="B", unit_scale=True, unit_divisor=1024
                ) as bar:
                    total = 0
                    for chunk in response.iter_content(256 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > 100 * 1024 * 1024:
                            raise RuntimeError("Tor bundle exceeded 100 MiB")
                        tmp.write(chunk)
                        digest.update(chunk)
                        bar.update(len(chunk))
            if digest.hexdigest().lower() != expected:
                raise RuntimeError("Tor bundle SHA-256 verification failed; archive discarded")
            self.bin_dir.mkdir(parents=True, exist_ok=True)
            self._safe_extract(archive_path, self.bin_dir)
        except (RequestException, OSError, tarfile.TarError) as exc:
            raise RuntimeError(f"Unable to install the official Tor Expert Bundle: {exc}") from exc
        finally:
            bootstrap.close()
            if "archive_path" in locals():
                archive_path.unlink(missing_ok=True)

        if os.name == "nt":
            with contextlib.suppress(Exception):
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(self.bin_dir), 0x02)
        binary = self._local_binary()
        if not binary:
            raise RuntimeError("Verified Tor archive did not contain the expected executable")
        if os.name != "nt":
            binary.chmod(binary.stat().st_mode | 0o111)
        LOG.info("Tor installed locally at %s", binary)
        return binary

    @staticmethod
    def _safe_extract(archive_path: Path, destination: Path) -> None:
        root = destination.resolve()
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                target = (root / member.name).resolve()
                if root != target and root not in target.parents:
                    raise RuntimeError(f"Unsafe path in Tor archive: {member.name}")
                if member.issym() or member.islnk():
                    raise RuntimeError(f"Links are not accepted in Tor archive: {member.name}")
                if member.isdev() or member.isfifo():
                    raise RuntimeError(f"Special file is not accepted in Tor archive: {member.name}")
            archive.extractall(root, members=members)

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def start(self) -> int:
        binary = self.locate_or_install()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.port = self._free_port()
        config: dict[str, str] = {
            "SocksPort": f"127.0.0.1:{self.port}",
            "DataDirectory": str(self.data_dir.resolve()),
            "ClientOnly": "1",
            "AvoidDiskWrites": "1",
            "Log": "NOTICE stdout",
        }
        # Expert Bundles ship GeoIP databases near the executable. System Tor
        # installations already know their packaged data paths.
        if self.bin_dir.resolve() in binary.parents:
            for filename, option in (("geoip", "GeoIPFile"), ("geoip6", "GeoIPv6File")):
                found = next((p for p in self.bin_dir.rglob(filename) if p.is_file()), None)
                if found:
                    config[option] = str(found.resolve())

        last_percent = -1
        def bootstrap_line(line: str) -> None:
            nonlocal last_percent
            match = re.search(r"Bootstrapped (\d+)%", line)
            if match:
                percent = int(match.group(1))
                if percent != last_percent:
                    print(f"\rTor bootstrap: {percent:3d}%", end="", flush=True)
                    last_percent = percent

        LOG.info("Starting private Tor runtime on 127.0.0.1:%s", self.port)
        try:
            self.process = launch_tor_with_config(
                config=config,
                tor_cmd=str(binary),
                completion_percent=100,
                init_msg_handler=bootstrap_line,
                timeout=self.bootstrap_timeout,
                take_ownership=True,
                close_output=True,
            )
        except OSError as exc:
            print()
            raise RuntimeError(f"Tor failed to bootstrap: {exc}") from exc
        print("\rTor bootstrap: 100% — connected")
        if not self._atexit_registered:
            atexit.register(self.stop)
            self._atexit_registered = True
        return self.port

    def stop(self) -> None:
        process, self.process = self.process, None
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


def user_agent() -> str:
    return random.choice(USER_AGENTS)


def make_session(proxy: str | None = None) -> Session:
    session = requests.Session()
    session.headers.update({"Accept": "*/*", "Accept-Language": "en-US,en;q=0.8"})
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def request(session: Session, method: str, url: str, **kwargs: object) -> Response:
    """Request with a freshly selected UA and conservative retry behavior."""
    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("User-Agent", user_agent())
    kwargs["headers"] = headers
    return session.request(method, url, **kwargs)


def is_onion(url: str) -> bool:
    host = (urlparse(url).hostname or "").rstrip(".").lower()
    return host.endswith(".onion")


def session_for(url: str, clear_session: Session, tor_session: Session) -> Session:
    # This routing decision is deliberately fail-closed for every onion URL.
    return tor_session if is_onion(url) else clear_session


def routed_get(
    url: str,
    clear_session: Session,
    tor_session: Session,
    timeout: float,
    *,
    stream: bool = False,
    max_redirects: int = 5,
) -> Response:
    """Follow redirects manually, choosing the safe session again at every hop."""
    current = url
    for _ in range(max_redirects + 1):
        response = request(
            session_for(current, clear_session, tor_session),
            "GET",
            current,
            stream=stream,
            timeout=timeout,
            allow_redirects=False,
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                return response
            next_url = urljoin(current, location)
            response.close()
            if urlparse(next_url).scheme not in ("http", "https"):
                raise RequestException(f"Refusing redirect to unsupported URL: {next_url}")
            current = next_url
            continue
        return response
    raise RequestException(f"Too many redirects while requesting {url}")


def verify_tor(tor_session: Session, port: int, timeout: float) -> None:
    """Require both a listening SOCKS port and a Tor-confirmed egress address."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=min(timeout, 5.0)):
            pass
    except OSError as exc:
        raise RuntimeError(f"Tor SOCKS proxy is not reachable on 127.0.0.1:{port}: {exc}") from exc

    try:
        response = request(
            tor_session, "GET", TOR_CHECK, timeout=timeout, allow_redirects=False
        )
        response.raise_for_status()
        result = response.json()
    except (RequestException, ValueError) as exc:
        raise RuntimeError(f"Could not verify Tor routing using {TOR_CHECK}: {exc}") from exc
    if not result.get("IsTor", False):
        raise RuntimeError(
            f"The proxy on port {port} responded, but Tor Project reports that its egress is not Tor"
        )
    LOG.info("Tor verified; exit address: %s", result.get("IP", "unknown"))


def unwrap_search_url(href: str, base: str) -> str | None:
    href = urljoin(base, href)
    parsed = urlparse(href)
    params = parse_qs(parsed.query)
    for key in ("uddg", "redirect_url", "url"):
        if params.get(key):
            candidate = unquote(params[key][0])
            if candidate.startswith(("http://", "https://")):
                return candidate
    if parsed.scheme in ("http", "https"):
        return href
    return None


def unique(items: Iterable[str]) -> Iterator[str]:
    seen: set[str] = set()
    for item in items:
        item = item.split("#", 1)[0]
        if item not in seen:
            seen.add(item)
            yield item


def links_from_html(html: bytes | str, base_url: str, pdf_only: bool = False) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    found: list[str] = []
    for anchor in soup.select("a[href]"):
        target = unwrap_search_url(str(anchor.get("href")), base_url)
        if not target:
            continue
        path = unquote(urlparse(target).path).lower()
        if not pdf_only or path.endswith(".pdf") or "filetype=pdf" in target.lower():
            found.append(target)
    return list(unique(found))


def clearnet_search(session: Session, query: str, limit: int, timeout: float) -> list[str]:
    searches = (f'{query} filetype:pdf', f'{query} intitle:"index of" pdf')
    results: list[str] = []
    for search_query in searches:
        try:
            response = request(
                session,
                "POST",
                DDG_HTML,
                data={"q": search_query},
                timeout=timeout,
                allow_redirects=False,
            )
            response.raise_for_status()
            results.extend(links_from_html(response.content, response.url))
        except (SSLError, RequestException) as exc:
            LOG.warning("DuckDuckGo search failed for %r: %s", search_query, exc)
        if len(list(unique(results))) >= limit * 2:
            break
    return list(unique(results))[: limit * 2]


def ahmia_search(
    clear_session: Session, tor_session: Session, query: str, limit: int, timeout: float
) -> list[str]:
    """Try Ahmia's onion service first, then its clear-web search frontend."""
    for base in (AHMIA_ONION, AHMIA_CLEAR):
        session = session_for(base, clear_session, tor_session)
        try:
            response = request(
                session,
                "GET",
                f"{base}/search/",
                params={"q": f"{query} filetype:pdf"},
                timeout=timeout,
                allow_redirects=False,
            )
            response.raise_for_status()
            links = links_from_html(response.content, response.url)
            # Keep external results; Ahmia navigation pages are not candidates.
            links = [u for u in links if urlparse(u).hostname not in {urlparse(base).hostname}]
            if links:
                return links[: limit * 3]
            LOG.warning("Ahmia at %s returned no candidate links", base)
        except (SSLError, RequestException) as exc:
            LOG.warning("Ahmia endpoint %s failed: %s", base, exc)
    return []


def safe_query_name(query: str) -> str:
    value = re.sub(r"[^\w.-]+", "_", query.strip(), flags=re.UNICODE).strip("._")
    return value[:100] or "pdf_search"


def safe_filename(url: str) -> str:
    name = unquote(Path(urlparse(url).path).name)
    name = re.sub(r"[^\w.() -]+", "_", name, flags=re.UNICODE).strip(" ._")
    if not name.lower().endswith(".pdf"):
        name = f"{name or 'document'}.pdf"
    return name[:180]


def existing_hashes(directory: Path) -> set[str]:
    hashes: set[str] = set()
    for path in directory.glob("*.pdf"):
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            hashes.add(digest.hexdigest())
        except OSError as exc:
            LOG.warning("Cannot hash existing file %s: %s", path, exc)
    return hashes


def available_path(directory: Path, filename: str, digest: str) -> Path:
    target = directory / filename
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    return directory / f"{stem}_{digest[:10]}{suffix}"


def content_length(response: Response) -> int | None:
    try:
        return int(response.headers["Content-Length"])
    except (KeyError, TypeError, ValueError):
        return None


def download_pdf(
    url: str,
    clear_session: Session,
    tor_session: Session,
    output_dir: Path,
    known_hashes: set[str],
    max_bytes: int,
    timeout: float,
    response: Response | None = None,
) -> Path | None:
    """Stream, validate, hash, and atomically retain a PDF."""
    temp_path: Path | None = None
    try:
        if response is None:
            response = routed_get(
                url,
                clear_session,
                tor_session,
                timeout,
                stream=True,
            )
        response.raise_for_status()
        declared = content_length(response)
        if declared is not None and declared > max_bytes:
            LOG.warning("Skipping oversized PDF (%s bytes): %s", declared, url)
            return None

        iterator = response.iter_content(chunk_size=128 * 1024)
        first = next(iterator, b"")
        if not first.startswith(PDF_MAGIC):
            LOG.debug("Not a PDF by magic bytes: %s", url)
            return None

        fd, raw_temp = tempfile.mkstemp(prefix=".pdf-osint-", suffix=".part", dir=output_dir)
        os.close(fd)
        temp_path = Path(raw_temp)
        digest = hashlib.sha256()
        total = 0
        with temp_path.open("wb") as handle, tqdm(
            total=declared,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=safe_filename(response.url)[:35],
            leave=False,
        ) as bar:
            for chunk in itertools.chain((first,), iterator):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    LOG.warning("Download exceeded size limit; discarded: %s", url)
                    return None
                handle.write(chunk)
                digest.update(chunk)
                bar.update(len(chunk))

        hexdigest = digest.hexdigest()
        if hexdigest in known_hashes:
            LOG.info("Duplicate content skipped: %s", url)
            return None
        target = available_path(output_dir, safe_filename(response.url), hexdigest)
        temp_path.replace(target)
        temp_path = None
        known_hashes.add(hexdigest)
        LOG.info("Saved %s (%s bytes)", target, total)
        return target
    except requests.HTTPError as exc:
        LOG.warning("HTTP error for %s: %s", url, exc)
    except SSLError as exc:
        LOG.warning("TLS error for %s: %s", url, exc)
    except (RequestException, OSError, RuntimeError) as exc:
        LOG.warning("Failed to download %s: %s", url, exc)
    finally:
        if response is not None:
            response.close()
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return None


def inspect_candidate(
    url: str,
    clear_session: Session,
    tor_session: Session,
    output_dir: Path,
    known_hashes: set[str],
    max_bytes: int,
    timeout: float,
) -> tuple[Path | None, list[str]]:
    """Download a direct PDF, or inspect a small HTML result page for PDF links."""
    response: Response | None = None
    try:
        response = routed_get(
            url,
            clear_session,
            tor_session,
            timeout,
            stream=True,
        )
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        path_says_pdf = unquote(urlparse(response.url).path).lower().endswith(".pdf")
        if "application/pdf" in content_type or path_says_pdf:
            saved = download_pdf(
                url,
                clear_session,
                tor_session,
                output_dir,
                known_hashes,
                max_bytes,
                timeout,
                response=response,
            )
            response = None
            return saved, []

        if "html" not in content_type and content_type:
            return None, []
        data = bytearray()
        for chunk in response.iter_content(64 * 1024):
            data.extend(chunk)
            if len(data) > HTML_INSPECTION_LIMIT:
                break
        if bytes(data).startswith(PDF_MAGIC):
            # A server omitted/misstated its type. Re-request to preserve streaming.
            return (
                download_pdf(
                    url,
                    clear_session,
                    tor_session,
                    output_dir,
                    known_hashes,
                    max_bytes,
                    timeout,
                ),
                [],
            )
        return None, links_from_html(bytes(data), response.url, pdf_only=True)
    except (SSLError, RequestException) as exc:
        LOG.warning("Dead/unreachable candidate %s: %s", url, exc)
        return None, []
    finally:
        if response is not None:
            response.close()


def run(config: Config) -> int:
    managed_tor: ManagedTor | None = None
    needs_tor = config.use_darkweb or config.all_through_tor
    try:
        if needs_tor:
            managed_tor = ManagedTor(Path.cwd())
            tor_port = managed_tor.start()
            proxy = f"socks5h://127.0.0.1:{tor_port}"
            tor_session = make_session(proxy)
            verify_tor(tor_session, tor_port, config.timeout)
        else:
            # This session is never selected because dark-web discovery is disabled.
            tor_session = make_session("socks5h://127.0.0.1:1")
        clear_session = tor_session if config.all_through_tor else make_session()

        destination = config.output_dir / safe_query_name(config.query)
        destination.mkdir(parents=True, exist_ok=True)
        hashes = existing_hashes(destination)

        candidates: list[str] = []
        if config.use_clearnet:
            candidates.extend(clearnet_search(clear_session, config.query, config.limit, config.timeout))
        if config.use_darkweb:
            candidates.extend(
                ahmia_search(clear_session, tor_session, config.query, config.limit, config.timeout)
            )
        queue = list(unique(candidates))
        queued = set(queue)
        downloaded: list[Path] = []

        # Bound page inspection so hostile/search-generated link graphs cannot grow forever.
        inspection_budget = max(config.limit * 5, 10)
        inspected = 0
        while queue and len(downloaded) < config.limit and inspected < inspection_budget:
            candidate = queue.pop(0)
            inspected += 1
            saved, discovered = inspect_candidate(
                candidate,
                clear_session,
                tor_session,
                destination,
                hashes,
                config.max_bytes,
                config.timeout,
            )
            if saved:
                downloaded.append(saved)
            for link in discovered:
                if link not in queued:
                    queued.add(link)
                    queue.append(link)

        manifest = {
            "query": config.query,
            "downloaded": [str(path) for path in downloaded],
            "download_count": len(downloaded),
            "candidates_inspected": inspected,
        }
        (destination / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        LOG.info("Finished: %s PDF(s) saved under %s", len(downloaded), destination)
        return 0 if downloaded else 2
    finally:
        if managed_tor is not None:
            managed_tor.stop()


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def parse_args(argv: list[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", "-q", required=True, help="Search keyword or topic")
    parser.add_argument("--limit", "-l", type=positive_int, default=5, help="Maximum PDFs to save")
    parser.add_argument(
        "--output", "-o", dest="output_dir", type=Path, default=Path("downloaded_pdfs")
    )
    parser.add_argument(
        "--source", choices=("both", "clearnet", "darknet"), default="both",
        help="Where to search (default: both)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="Connect/read timeout in seconds")
    parser.add_argument("--max-size-mb", type=positive_int, default=50)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    return Config(
        query=args.query,
        limit=args.limit,
        output_dir=args.output_dir.expanduser(),
        timeout=args.timeout,
        max_bytes=args.max_size_mb * 1024 * 1024,
        use_clearnet=args.source in {"both", "clearnet"},
        use_darkweb=args.source in {"both", "darknet"},
        all_through_tor=False,
    )


def main() -> int:
    try:
        return run(parse_args())
    except (KeyboardInterrupt, RuntimeError) as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

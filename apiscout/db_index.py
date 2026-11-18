"""the folder for downloaded API DBs, the index of the DBs in the repository and their download

The repository's dbs folder holds SHA256SUMS, which lists every file of the folder with its SHA-256
(check with `sha256sum -c SHA256SUMS`). Downloads are checked against it. After a change to the folder, rewrite it with:

    python -m apiscout.db_index dbs
"""

import hashlib
import os
import re
import sys

INDEX_NAME = "SHA256SUMS"
# no file of the repository comes close, a larger download is cut off
MAX_SIZE = 1 << 28
MAX_INDEX_SIZE = 1 << 20
SOURCE_URL = "https://raw.githubusercontent.com/danielplohmann/apiscout/{ref}/dbs/"
CHUNK_SIZE = 1 << 20


def get_data_dir():
    """the folder downloaded API DBs are stored in, following the conventions of the OS"""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "apiscout", "dbs")


def get_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f_in:
        for chunk in iter(lambda: f_in.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_index(folder):
    """name and SHA-256 of every file of the folder, in the format of sha256sum"""
    names = sorted(name for name in os.listdir(folder) if name != INDEX_NAME and not name.startswith("."))
    return "".join(f"{get_sha256(os.path.join(folder, name))}  {name}\n" for name in names)


def write_index(folder):
    with open(os.path.join(folder, INDEX_NAME), "w", encoding="utf-8", newline="\n") as f_out:
        f_out.write(build_index(folder))


def parse_index(text):
    files = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\]+)", line.strip())
        if not match or match.group(2) in (".", ".."):
            raise ValueError(line)
        files[match.group(2)] = match.group(1)
    return files


class DownloadError(Exception):
    pass


def _open(url, timeout):
    # the network modules cost more than everything else of a command that does not download
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": "apiscout"})
    try:
        return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 - the URL is https, built from SOURCE_URL
    except urllib.error.HTTPError as exc:
        raise DownloadError(f"{url}: HTTP {exc.code} {exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DownloadError(f"{url}: {reason}") from exc


def fetch_index(ref, timeout=60):
    """the files of the repository's dbs folder: name -> SHA-256"""
    import http.client

    url = SOURCE_URL.format(ref=ref) + INDEX_NAME
    with _open(url, timeout) as response:
        try:
            text = response.read(MAX_INDEX_SIZE).decode("utf-8")
        except (OSError, http.client.HTTPException) as exc:
            raise DownloadError(f"{url}: download interrupted ({exc})") from exc
        except ValueError as exc:
            raise DownloadError(f"{url}: not a list of SHA-256 sums") from exc
    try:
        return parse_index(text)
    except ValueError as exc:
        raise DownloadError(f"{url}: not a list of SHA-256 sums") from exc


def is_current(path, sha256):
    return os.path.isfile(path) and get_sha256(path) == sha256


def download(ref, name, sha256, folder, timeout=60):
    """download one file of the index into folder; it only replaces an existing file once the SHA-256 matches"""
    import http.client
    import tempfile

    url = SOURCE_URL.format(ref=ref) + name
    digest = hashlib.sha256()
    size = 0
    handle, temp_path = tempfile.mkstemp(prefix=".download-", dir=folder)
    try:
        with os.fdopen(handle, "wb") as f_out, _open(url, timeout) as response:
            while True:
                try:
                    chunk = response.read(CHUNK_SIZE)
                except (OSError, http.client.HTTPException) as exc:
                    raise DownloadError(f"{url}: download interrupted ({exc})") from exc
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_SIZE:
                    raise DownloadError(f"{url}: larger than {MAX_SIZE} bytes, not an API DB")
                digest.update(chunk)
                f_out.write(chunk)
        if digest.hexdigest() != sha256:
            raise DownloadError(f"{url}: the SHA-256 differs from {INDEX_NAME}, the file was not stored")
        # mkstemp creates files only the owner can read, DBs are not secret
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, os.path.join(folder, name))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


if __name__ == "__main__":
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        sys.exit("usage: python -m apiscout.db_index <dbs folder>")
    write_index(sys.argv[1])

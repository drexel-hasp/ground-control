#!/usr/bin/env python3
"""Flask web app — HASP Downlink Decoder control panel.

Large captures are decoded into a temporary SQLite dataset. The browser only
requests one newest-first page at a time, while charts receive a bounded sample
and CSV export streams directly from the dataset.
"""

from __future__ import annotations

import atexit
import csv
import io
import json
import math
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from flask import Flask, Response, abort, jsonify, render_template, request, stream_with_context

from constants import CSV_HEADER
from decoder import decode_binary_increment, decode_path, decode_status, decode_text

app = Flask(__name__)

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
MAX_CHART_POINTS = 2000
MAX_DATASETS = 8
DATASET_TTL_SECONDS = 6 * 60 * 60
LIVE_HTTP_TIMEOUT_SECONDS = 20
MAX_LIVE_FETCH_BYTES = 5 * 1024 * 1024
DEFAULT_LIVE_INITIAL_PACKETS = 1000
MAX_LIVE_INITIAL_PACKETS = 10000
LIVE_USER_AGENT = "HASP-Ground-Control/1.0"

_cache_root = Path(tempfile.mkdtemp(prefix="hasp-ground-control-"))
_datasets: dict[str, dict[str, object]] = {}
_datasets_lock = threading.Lock()
atexit.register(lambda: shutil.rmtree(_cache_root, ignore_errors=True))


def _normalize_row(row: dict[str, object]) -> dict[str, object]:
    row["crc_ok"] = bool(row["crc_ok"])
    row["frame_ok"] = bool(row["frame_ok"])
    return row


def _dataset_path(dataset_id: str) -> Path:
    with _datasets_lock:
        info = _datasets.get(dataset_id)
    if not info:
        abort(404, description="Dataset not found or expired")
    return Path(info["path"])


def _delete_dataset(dataset_id: str) -> None:
    with _datasets_lock:
        info = _datasets.pop(dataset_id, None)
    if info:
        Path(info["path"]).unlink(missing_ok=True)


def _prune_datasets() -> None:
    now = time.time()
    with _datasets_lock:
        expired = [
            dataset_id
            for dataset_id, info in _datasets.items()
            if now - float(info["created_at"]) > DATASET_TTL_SECONDS
        ]
        remaining = sorted(
            (
                (float(info["created_at"]), dataset_id)
                for dataset_id, info in _datasets.items()
                if dataset_id not in expired
            ),
            reverse=True,
        )
        expired.extend(dataset_id for _, dataset_id in remaining[MAX_DATASETS - 1 :])
    for dataset_id in expired:
        _delete_dataset(dataset_id)


def _new_dataset() -> tuple[str, Path, sqlite3.Connection]:
    _prune_datasets()
    dataset_id = uuid.uuid4().hex
    path = _cache_root / f"{dataset_id}.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE packets (packet_number INTEGER PRIMARY KEY, crc_ok INTEGER NOT NULL, data TEXT NOT NULL)"
    )
    return dataset_id, path, connection


def _store_rows(rows: list[dict[str, object]], decoded: int, ignored: int) -> str:
    dataset_id, path, connection = _new_dataset()
    try:
        connection.executemany(
            "INSERT INTO packets VALUES (?, ?, ?)",
            (
                (
                    int(row["packet_number"]),
                    int(bool(row["crc_ok"])),
                    json.dumps(_normalize_row(row), separators=(",", ":")),
                )
                for row in rows
            ),
        )
        connection.commit()
        failed = connection.execute("SELECT COUNT(*) FROM packets WHERE crc_ok = 0").fetchone()[0]
    finally:
        connection.close()

    with _datasets_lock:
        _datasets[dataset_id] = {
            "path": str(path),
            "created_at": time.time(),
            "decoded": decoded,
            "ignored": ignored,
            "crc_failed": failed,
        }
    return dataset_id


def _store_file(source_path: Path) -> str:
    dataset_id, path, connection = _new_dataset()
    pending: list[tuple[int, int, str]] = []
    failed = 0

    def add_row(row: dict[str, object]) -> None:
        nonlocal failed
        normalized = _normalize_row(row)
        failed += int(not normalized["crc_ok"])
        pending.append(
            (
                int(normalized["packet_number"]),
                int(bool(normalized["crc_ok"])),
                json.dumps(normalized, separators=(",", ":")),
            )
        )
        if len(pending) >= 1000:
            connection.executemany("INSERT INTO packets VALUES (?, ?, ?)", pending)
            pending.clear()

    try:
        decoded, ignored = decode_path(source_path, add_row)
        if pending:
            connection.executemany("INSERT INTO packets VALUES (?, ?, ?)", pending)
        connection.commit()
    except Exception:
        connection.close()
        path.unlink(missing_ok=True)
        raise
    finally:
        try:
            connection.close()
        except sqlite3.Error:
            pass

    with _datasets_lock:
        _datasets[dataset_id] = {
            "path": str(path),
            "created_at": time.time(),
            "decoded": decoded,
            "ignored": ignored,
            "crc_failed": failed,
        }
    return dataset_id


def _create_empty_dataset() -> str:
    dataset_id, path, connection = _new_dataset()
    connection.commit()
    connection.close()
    with _datasets_lock:
        _datasets[dataset_id] = {
            "path": str(path),
            "created_at": time.time(),
            "decoded": 0,
            "ignored": 0,
            "crc_failed": 0,
        }
    return dataset_id


def _append_dataset_rows(
    dataset_id: str,
    rows: list[dict[str, object]],
    ignored: int = 0,
    *,
    reset: bool = False,
) -> None:
    path = _dataset_path(dataset_id)
    normalized_rows = [_normalize_row(row) for row in rows]
    failed = sum(not row["crc_ok"] for row in normalized_rows)
    with sqlite3.connect(path) as connection:
        if reset:
            connection.execute("DELETE FROM packets")
        connection.executemany(
            "INSERT INTO packets VALUES (?, ?, ?)",
            (
                (
                    int(row["packet_number"]),
                    int(bool(row["crc_ok"])),
                    json.dumps(row, separators=(",", ":")),
                )
                for row in normalized_rows
            ),
        )
        connection.commit()

    with _datasets_lock:
        info = _datasets[dataset_id]
        if reset:
            info["decoded"] = 0
            info["ignored"] = 0
            info["crc_failed"] = 0
        info["decoded"] = int(info["decoded"]) + len(normalized_rows)
        info["ignored"] = int(info["ignored"]) + ignored
        info["crc_failed"] = int(info["crc_failed"]) + failed


def _validate_live_url(value: object) -> str:
    url = str(value or "").strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete http:// or https:// log URL")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported")
    return url


def _remote_metadata(url: str) -> dict[str, object]:
    request_object = Request(
        url,
        method="HEAD",
        headers={"User-Agent": LIVE_USER_AGENT, "Accept-Encoding": "identity"},
    )
    with urlopen(request_object, timeout=LIVE_HTTP_TIMEOUT_SECONDS) as response:
        content_length = response.headers.get("Content-Length")
        if content_length is None:
            raise ValueError("Remote server did not provide Content-Length")
        if "bytes" not in response.headers.get("Accept-Ranges", "").lower():
            raise ValueError("Remote server does not advertise byte-range support")
        return {
            "size": int(content_length),
            "etag": response.headers.get("ETag", ""),
            "last_modified": response.headers.get("Last-Modified", ""),
        }


def _remote_range(url: str, start: int, end: int) -> tuple[bytes, int]:
    request_object = Request(
        url,
        headers={
            "User-Agent": LIVE_USER_AGENT,
            "Accept-Encoding": "identity",
            "Range": f"bytes={start}-{end}",
        },
    )
    with urlopen(request_object, timeout=LIVE_HTTP_TIMEOUT_SECONDS) as response:
        if response.status != 206:
            raise ValueError("Remote server ignored the byte-range request")
        content_range = response.headers.get("Content-Range", "")
        match = re.fullmatch(r"bytes\s+(\d+)-(\d+)/(?:\d+|\*)", content_range)
        if not match or int(match.group(1)) != start:
            raise ValueError("Remote server returned an unexpected byte range")
        actual_end = int(match.group(2))
        data = response.read((actual_end - start + 1) + 1)
        if len(data) != actual_end - start + 1:
            raise ValueError("Remote byte-range response was incomplete")
        return data, actual_end


def _normalize_live_status(row: dict[str, object]) -> dict[str, object]:
    # The downloaded tail starts in the middle of a flight. Sequence number is
    # therefore the reliable rolling-status phase, while packet_number remains
    # the monotonic index within this live viewing session.
    row.update(
        decode_status(
            int(row["status_type"]),
            int(row["status_data"]),
            int(row["sequence_number"]) + 1,
        )
    )
    return row


def _ingest_live_range(
    dataset_id: str,
    url: str,
    start: int,
    end: int,
    *,
    reset: bool = False,
) -> tuple[list[dict[str, object]], int]:
    data, actual_end = _remote_range(url, start, end)
    with _datasets_lock:
        info = _datasets[dataset_id]
        live = dict(info.get("live", {}))
        pending = b"" if reset else bytes(live.get("pending", b""))
        next_packet_number = 1 if reset else int(info["decoded"]) + 1

    rows, ignored, pending = decode_binary_increment(
        pending + data,
        next_packet_number,
    )
    rows = [_normalize_live_status(row) for row in rows]
    _append_dataset_rows(dataset_id, rows, ignored, reset=reset)
    with _datasets_lock:
        live = _datasets[dataset_id].setdefault("live", {})
        live["pending"] = pending
        live["remote_offset"] = actual_end + 1
    return rows, actual_end + 1


def _page_size() -> int:
    try:
        return max(25, min(MAX_PAGE_SIZE, int(request.args.get("page_size", DEFAULT_PAGE_SIZE))))
    except ValueError:
        return DEFAULT_PAGE_SIZE


def _page_payload(dataset_id: str, page: int, page_size: int) -> dict[str, object]:
    path = _dataset_path(dataset_id)
    with _datasets_lock:
        info = dict(_datasets[dataset_id])
    total = int(info["decoded"])
    page_count = max(1, math.ceil(total / page_size))
    page = max(1, min(page_count, page))
    offset = (page - 1) * page_size

    with sqlite3.connect(path) as connection:
        records = connection.execute(
            "SELECT data FROM packets ORDER BY packet_number DESC LIMIT ? OFFSET ?",
            (page_size, offset),
        ).fetchall()

    return {
        "dataset_id": dataset_id,
        "packets": [json.loads(record[0]) for record in records],
        "decoded": total,
        "ignored": int(info["ignored"]),
        "crc_failed": int(info["crc_failed"]),
        "page": page,
        "page_size": page_size,
        "page_count": page_count,
    }


def _chart_rows(dataset_id: str) -> list[dict[str, object]]:
    path = _dataset_path(dataset_id)
    with _datasets_lock:
        total = int(_datasets[dataset_id]["decoded"])
    if not total:
        return []
    stride = max(1, math.ceil(total / MAX_CHART_POINTS))
    with sqlite3.connect(path) as connection:
        records = connection.execute(
            """
            SELECT data FROM packets
            WHERE ((packet_number - 1) % ?) = 0 OR packet_number = ?
            ORDER BY packet_number ASC
            """,
            (stride, total),
        ).fetchall()
    return [json.loads(record[0]) for record in records]


@app.route("/")
def index():
    return render_template("index.html", csv_header=CSV_HEADER)


@app.route("/decode", methods=["POST"])
def decode():
    if "file" in request.files:
        upload = request.files["file"]
        suffix = Path(upload.filename or "capture.bin").suffix
        source_path = _cache_root / f"upload-{uuid.uuid4().hex}{suffix}"
        try:
            upload.save(source_path)
            dataset_id = _store_file(source_path)
        finally:
            source_path.unlink(missing_ok=True)
    else:
        text = (request.get_json(silent=True) or {}).get("text", "")
        rows, decoded, ignored = decode_text(text)
        dataset_id = _store_rows(rows, decoded, ignored)

    payload = _page_payload(dataset_id, 1, _page_size())
    payload["chart_packets"] = _chart_rows(dataset_id)
    return jsonify(payload)


@app.route("/live/start", methods=["POST"])
def start_live():
    body = request.get_json(silent=True) or {}
    try:
        url = _validate_live_url(body.get("url"))
        initial_packets = max(
            100,
            min(MAX_LIVE_INITIAL_PACKETS, int(body.get("initial_packets", DEFAULT_LIVE_INITIAL_PACKETS))),
        )
        metadata = _remote_metadata(url)
        dataset_id = _create_empty_dataset()
        try:
            remote_size = int(metadata["size"])
            remote_offset = 0
            if remote_size:
                start = max(0, remote_size - (initial_packets * 50 + 49))
                _, remote_offset = _ingest_live_range(
                    dataset_id,
                    url,
                    start,
                    remote_size - 1,
                )
            with _datasets_lock:
                _datasets[dataset_id].setdefault("live", {}).update(
                    {
                        "url": url,
                        "active": True,
                        "remote_offset": remote_offset,
                        "remote_size": remote_size,
                        "etag": metadata["etag"],
                        "last_modified": metadata["last_modified"],
                        "last_checked": time.time(),
                        "initial_packets": initial_packets,
                    }
                )
        except Exception:
            _delete_dataset(dataset_id)
            raise
    except (ValueError, HTTPError, URLError, TimeoutError) as error:
        return jsonify(error=str(error)), 400

    payload = _page_payload(dataset_id, 1, _page_size())
    payload["chart_packets"] = _chart_rows(dataset_id)
    payload["live"] = {
        "url": url,
        "remote_size": remote_size,
        "last_modified": metadata["last_modified"],
    }
    return jsonify(payload)


@app.route("/datasets/<dataset_id>/poll", methods=["POST"])
def poll_live(dataset_id: str):
    _dataset_path(dataset_id)
    with _datasets_lock:
        live = dict(_datasets[dataset_id].get("live", {}))
    if not live or not live.get("active"):
        return jsonify(error="Live polling is not active for this dataset"), 409

    url = str(live["url"])
    reset = False
    rows: list[dict[str, object]] = []
    try:
        metadata = _remote_metadata(url)
        remote_size = int(metadata["size"])
        remote_offset = int(live.get("remote_offset", 0))

        if remote_size < remote_offset:
            reset = True
            initial_packets = int(live.get("initial_packets", DEFAULT_LIVE_INITIAL_PACKETS))
            if remote_size:
                start = max(0, remote_size - (initial_packets * 50 + 49))
                rows, remote_offset = _ingest_live_range(
                    dataset_id,
                    url,
                    start,
                    remote_size - 1,
                    reset=True,
                )
            else:
                _append_dataset_rows(dataset_id, [], reset=True)
                remote_offset = 0
                with _datasets_lock:
                    _datasets[dataset_id]["live"]["pending"] = b""
        elif remote_size > remote_offset:
            end = min(remote_size - 1, remote_offset + MAX_LIVE_FETCH_BYTES - 1)
            rows, remote_offset = _ingest_live_range(
                dataset_id,
                url,
                remote_offset,
                end,
            )

        checked_at = time.time()
        with _datasets_lock:
            info = _datasets[dataset_id]
            info["created_at"] = checked_at
            info["live"].update(
                {
                    "remote_offset": remote_offset,
                    "remote_size": remote_size,
                    "etag": metadata["etag"],
                    "last_modified": metadata["last_modified"],
                    "last_checked": checked_at,
                }
            )
            decoded = int(info["decoded"])
            ignored = int(info["ignored"])
            crc_failed = int(info["crc_failed"])
    except (ValueError, HTTPError, URLError, TimeoutError) as error:
        return jsonify(error=str(error)), 502

    return jsonify(
        dataset_id=dataset_id,
        new_packets=rows,
        new_count=len(rows),
        decoded=decoded,
        ignored=ignored,
        crc_failed=crc_failed,
        reset=reset,
        remote_size=remote_size,
        remote_offset=remote_offset,
        caught_up=remote_offset >= remote_size,
        last_modified=metadata["last_modified"],
    )


@app.route("/datasets/<dataset_id>/live/stop", methods=["POST"])
def stop_live(dataset_id: str):
    _dataset_path(dataset_id)
    with _datasets_lock:
        live = _datasets[dataset_id].get("live")
        if live:
            live["active"] = False
    return ("", 204)


@app.route("/datasets/<dataset_id>/packets")
def dataset_packets(dataset_id: str):
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1
    return jsonify(_page_payload(dataset_id, page, _page_size()))


@app.route("/datasets/<dataset_id>/csv")
def dataset_csv(dataset_id: str):
    path = _dataset_path(dataset_id)

    @stream_with_context
    def generate():
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_HEADER)
        writer.writeheader()
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        with sqlite3.connect(path) as connection:
            cursor = connection.execute("SELECT data FROM packets ORDER BY packet_number ASC")
            for (data,) in cursor:
                writer.writerow(json.loads(data))
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=downlink_decoded.csv"},
    )


@app.route("/datasets/<dataset_id>", methods=["DELETE"])
def delete_dataset(dataset_id: str):
    _delete_dataset(dataset_id)
    return ("", 204)


if __name__ == "__main__":
    import webbrowser

    threading.Timer(0.6, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(debug=False, port=5000)

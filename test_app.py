from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from app import app
from test_decoder import make_packet


class DatasetApiTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_index_renders_pagination_controls(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="pagination-bar"', response.data)
        self.assertIn(b'id="live-url"', response.data)
        self.assertIn(b'id="live-interval"', response.data)
        self.assertIn(b'id="tab-btn-summary"', response.data)
        self.assertIn(b"newest packets first", response.data)

    def test_summary_endpoint_uses_decoded_dataset(self) -> None:
        capture = b"".join(make_packet(i) for i in range(1, 101))
        decoded = self.client.post(
            "/decode", data={"file": (io.BytesIO(capture), "capture.bin")}
        ).get_json()

        response = self.client.get(f"/datasets/{decoded['dataset_id']}/summary")
        summary = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(summary["available"])
        self.assertEqual(summary["latest_sequence"], 100)

    def test_large_upload_opens_on_newest_page_and_pages_backwards(self) -> None:
        capture = b"".join(make_packet(i) for i in range(1, 251))
        response = self.client.post(
            "/decode?page_size=100",
            data={"file": (io.BytesIO(capture), "capture.bin")},
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["decoded"], 250)
        self.assertEqual(data["page_count"], 3)
        self.assertEqual(len(data["packets"]), 100)
        self.assertEqual(data["packets"][0]["sequence_number"], 250)
        self.assertEqual(data["packets"][-1]["sequence_number"], 151)

        older = self.client.get(
            f"/datasets/{data['dataset_id']}/packets?page=2&page_size=100"
        ).get_json()
        self.assertEqual(older["packets"][0]["sequence_number"], 150)
        self.assertEqual(older["packets"][-1]["sequence_number"], 51)

    def test_csv_export_contains_entire_dataset_in_capture_order(self) -> None:
        capture = b"".join(make_packet(i) for i in range(1, 121))
        data = self.client.post(
            "/decode?page_size=50",
            data={"file": (io.BytesIO(capture), "capture.bin")},
        ).get_json()

        response = self.client.get(f"/datasets/{data['dataset_id']}/csv")
        lines = response.get_data(as_text=True).splitlines()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(lines), 121)
        self.assertTrue(lines[1].startswith("1,1,"))
        self.assertTrue(lines[-1].startswith("120,120,"))

    def test_live_poll_fetches_only_appended_range_and_keeps_partial_packet(self) -> None:
        remote = bytearray(b"".join(make_packet(i) for i in range(1, 11)))
        remote.extend(make_packet(11)[:20])
        range_starts = []

        def metadata(_url):
            return {"size": len(remote), "etag": "changing", "last_modified": "now"}

        def byte_range(_url, start, end):
            range_starts.append(start)
            actual_end = min(end, len(remote) - 1)
            return bytes(remote[start : actual_end + 1]), actual_end

        with patch("app._remote_metadata", side_effect=metadata), patch(
            "app._remote_range", side_effect=byte_range
        ):
            started = self.client.post(
                "/live/start?page_size=50",
                json={"url": "https://example.test/live.log", "initial_packets": 100},
            ).get_json()
            initial_size = len(remote)
            self.assertEqual(started["decoded"], 10)

            remote.extend(make_packet(11)[20:] + make_packet(12))
            polled = self.client.post(
                f"/datasets/{started['dataset_id']}/poll"
            ).get_json()

        self.assertEqual(range_starts[-1], initial_size)
        self.assertEqual(polled["new_count"], 2)
        self.assertEqual(polled["decoded"], 12)
        self.assertEqual(
            [row["sequence_number"] for row in polled["new_packets"]],
            [11, 12],
        )
        self.assertTrue(polled["caught_up"])

    def test_live_poll_resets_when_remote_file_is_truncated(self) -> None:
        remote = bytearray(b"".join(make_packet(i) for i in range(1, 21)))

        def metadata(_url):
            return {"size": len(remote), "etag": "changing", "last_modified": "now"}

        def byte_range(_url, start, end):
            actual_end = min(end, len(remote) - 1)
            return bytes(remote[start : actual_end + 1]), actual_end

        with patch("app._remote_metadata", side_effect=metadata), patch(
            "app._remote_range", side_effect=byte_range
        ):
            started = self.client.post(
                "/live/start",
                json={"url": "https://example.test/live.log"},
            ).get_json()
            remote[:] = make_packet(90) + make_packet(91)
            polled = self.client.post(
                f"/datasets/{started['dataset_id']}/poll"
            ).get_json()

        self.assertTrue(polled["reset"])
        self.assertEqual(polled["decoded"], 2)
        self.assertEqual(
            [row["sequence_number"] for row in polled["new_packets"]],
            [90, 91],
        )


if __name__ == "__main__":
    unittest.main()

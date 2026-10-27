"""Verify that report output cannot overwrite capture evidence through aliases."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

EXECUTABLE = str(Path(sys.argv.pop(1)).resolve())


class EvidenceOverwriteTests(unittest.TestCase):
    def test_output_aliases_preserve_capture(self):
        for alias in ("same", "relative", "hardlink"):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture = root / "capture.pcap"
                original = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                capture.write_bytes(original)
                if alias == "hardlink":
                    output = root / "report.json"
                    os.link(capture, output)
                elif alias == "relative":
                    output = "./capture.pcap"
                else:
                    output = capture
                result = subprocess.run(
                    [EXECUTABLE, "scan", str(capture), "--format", "json", "--output", str(output)],
                    cwd=root, capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("refusing to overwrite evidence", result.stderr)
                self.assertEqual(capture.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

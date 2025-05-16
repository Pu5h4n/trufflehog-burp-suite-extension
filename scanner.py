#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A dummy TruffleHog scanner.
Monitors the provided temporary directory for paired header/body files.
If the body file contains the word "secret" (case-insensitive),
it outputs a JSON result.

Usage:
    python scanner.py --tempdir <temp_directory>
                      --trufflehog-path <path_to_trufflehog_binary>
                      [--only-verified]
                      [--allow-verification-overlap]
"""

import argparse
import os
import time
import json
import sys

def scan_temp_files(tempdir, trufflehog_path, only_verified, allow_overlap):
    results = {"results": []}
    HEADER_SUFFIX = "_headers.txt"
    BODY_SUFFIX = "_body.txt"

    # Identify unique IDs based on header file naming
    try:
        files = os.listdir(tempdir)
    except Exception as e:
        sys.stderr.write("Error listing temp directory: " + str(e) + "\n")
        return

    ids = set(f[:-len(HEADER_SUFFIX)] for f in files if f.endswith(HEADER_SUFFIX))
    for file_id in ids:
        header_file = os.path.join(tempdir, file_id + HEADER_SUFFIX)
        body_file = os.path.join(tempdir, file_id + BODY_SUFFIX)
        try:
            with open(body_file, "rb") as f:
                body_content = f.read()
        except Exception:
            continue

        # Dummy check: if the body file contains "secret", simulate a secret detected
        if b"secret" in body_content.lower():
            result = {
                "secretType": "Dummy Secret",
                "raw": "secret_value",
                "redacted": "******",
                "verified": True if only_verified else False,
                "decoderType": "dummy_decoder",
                "detectorDescription": "A dummy secret detected.",
                "extraData": {}
            }
            results["results"].append(result)

        # Clean up the temporary files after processing
        try:
            os.remove(header_file)
        except Exception:
            pass
        try:
            os.remove(body_file)
        except Exception:
            pass

    if results["results"]:
        # Output result with the file id so the extension can correlate it
        print(json.dumps({"id": file_id, "results": results["results"]}))
        sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="Dummy TruffleHog Scanner")
    parser.add_argument("--tempdir", required=True, help="Temporary directory path.")
    parser.add_argument("--trufflehog-path", required=True, help="Path to the TruffleHog binary (for verification).")
    parser.add_argument("--only-verified", action="store_true", help="Set if only verified secrets should be reported.")
    parser.add_argument("--allow-verification-overlap", action="store_true", help="Set if overlapping verification is allowed.")
    args = parser.parse_args()

    if not os.path.exists(args.trufflehog_path):
        sys.stderr.write("TruffleHog binary not found at path: " + args.trufflehog_path + "\n")
        sys.exit(1)

    # Continuously scan for new temp files, every 2 seconds
    while True:
        scan_temp_files(args.tempdir, args.trufflehog_path, args.only_verified, args.allow_verification_overlap)
        time.sleep(2)

if __name__ == "__main__":
    main()

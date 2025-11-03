#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""
verifier_diff.py

Compares two eBPF verifier log files and visualizes the number of verified
instructions between the two runs per function and program build.
This script accepts two JSON files, `main.json` and `patch.json`,
supposedly run before and after a code change, and creates an output directory
containing all the plots.
Running verifier tests locally would output a resulting JSON file under
`/tmp/verifier-complexity*/verifier-complexity.json`. As an alternative, these
JSON files can be obtained from CI runs.

Usage:
    python verifier_diff.py main.json patch.json
"""

import os
import argparse
import shutil
import json
import numpy as np
import matplotlib.pyplot as plt
import datetime
import logging


def load_json(file_path) -> dict:
    """
    Load JSON data from a file.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        dict: Parsed JSON data.
    """
    with open(file_path, "r") as f:
        return json.load(f)


def organize_data(data, key: str) -> dict:
    """
    Organize data into dict keyed by (collection, build, load, program).

    Args:
        data (list): List of JSON entries.

    Returns:
        dict: Organized data.
    """
    organized = {}
    for entry in data:
        if not key in entry:
            logging.error(f"Key '{key}' not found in data.")
            break
        if not isinstance(entry[key], (int, float)) or not str(entry[key]).isnumeric():
            logging.error(f"Key '{key}' doesn't have a numeric value.")
            break
        k = (entry["collection"], entry["build"],
             entry["load"], entry["program"])
        organized[k] = int(entry[key])
    return organized


def plot_comparison(file1: str, file2: str, key: str, outdir: str):
    """Plot comparison of eBPF verifier logs.

    Args:
        file1 (str): Path to the first JSON file.
        file2 (str): Path to the second JSON file.
        outdir (str): Output directory for the plots.
    """
    data1 = organize_data(load_json(file1), key)
    data2 = organize_data(load_json(file2), key)

    # Collect all unique (collection, build, load) triples
    groups = set((c, b, l) for c, b, l, _ in data1.keys()) | set(
        (c, b, l) for c, b, l, _ in data2.keys())

    for collection, build, load in groups:
        # Collect all programs for this collection/build/load
        programs = sorted(set(
            [p for c, b, l, p in data1.keys()
             if c == collection and b == build and l == load] +
            [p for c, b, l, p in data2.keys()
             if c == collection and b == build and l == load]
        ))

        if not programs:
            logging.debug(
                f"No programs found for collection {collection}, "
                f"build {build}, load {load}, skipping.")
            continue

        before_vals = []
        after_vals = []
        filtered_programs = []

        for prog in programs:
            v1 = data1.get((collection, build, load, prog), 0)
            v2 = data2.get((collection, build, load, prog), 0)
            if v1 == v2:
                logging.debug(
                    f"Program {prog} unchanged ({v1}) for "
                    f"collection {collection}, build {build}, "
                    f"load {load}, skipping.")
                continue  # skip unchanged values
            filtered_programs.append(prog)
            before_vals.append(v1)
            after_vals.append(v2)

        if not filtered_programs:  # skip if all values unchanged
            logging.info(
                f"All programs unchanged for collection {collection} "
                f"build {build} load {load}, skipping.")
            continue

        # Plot
        y_pos = np.arange(len(filtered_programs))
        bar_height = 0.35
        fig_width = 10
        fig_height = min(fig_width, max(fig_width//2,
                                        bar_height * len(filtered_programs)))

        plt.figure(figsize=(fig_width, fig_height))
        bars_before = plt.barh(y_pos + bar_height/2, before_vals,
                               bar_height, label="Before", alpha=0.7)
        bars_after = plt.barh(y_pos - bar_height/2, after_vals,
                              bar_height, label="After", alpha=0.7)

        plt.yticks(y_pos, filtered_programs)
        plt.xlabel(key)
        plt.title(f"Collection {collection} - Build {build} - Load {load}")
        plt.legend()

        # Add text labels at the end of bars
        max_val = max(before_vals + after_vals)
        for bar in bars_before:
            width = bar.get_width()
            plt.text(width + max_val * 0.01, bar.get_y() + bar.get_height()/2,
                     f"{width}", va="center", ha="left", fontsize=8)

        for bar in bars_after:
            width = bar.get_width()
            plt.text(width + max_val * 0.01, bar.get_y() + bar.get_height()/2,
                     f"{width}", va="center", ha="left", fontsize=8)

        plt.tight_layout()
        build_dir = os.path.join(outdir, collection, f"build{build}")
        os.makedirs(build_dir, exist_ok=True)
        outfile = os.path.join(build_dir, f"states-load{load}.png")
        plt.savefig(outfile)
        plt.close()
        logging.info(f"Saved plot: {outfile}")


def setup_output_dir(file_after: str, file_before: str) -> str:
    """
    Generates a unique output directory name using input file names and current
    timestamp. Also, stores a copy of the log files in the new directory.

    Args:
        file_after (str): Path to the "after" verifier log.
        file_before (str): Path to the "before" verifier log.

    Returns:
        str: Name of the new output directory.
    """
    base_after = os.path.basename(file_after).replace('.', '_')
    base_before = os.path.basename(file_before).replace('.', '_')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"insn-diff-{base_after}-wrt-{base_before}-{timestamp}"

    os.makedirs(output_dir, exist_ok=True)
    logging.info(f"Output directory {output_dir} created.")

    shutil.copy(file_before, output_dir)
    shutil.copy(file_after, output_dir)
    logging.info("Log files successfully backed up.")
    return output_dir


def main():
    """
    Entry point for the script. Parses arguments, sets up logging,
    and runs comparison and visualization.
    """
    parser = argparse.ArgumentParser(
        description="Compare number of verified instructions " +
        "from eBPF verifier logs.")
    parser.add_argument("file_before", help="Path to the log before patch")
    parser.add_argument("file_after", help="Path to the log after patch")
    parser.add_argument('-v', '--verbose', action='store_true', help="Print debug logs.")
    parser.add_argument('--key', default="insns_processed", help="Verifier statistic to compare (ex., peak_states, verification_time_microseconds).")

    args = parser.parse_args()

    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    output_dir = setup_output_dir(args.file_after, args.file_before)

    plot_comparison(args.file_before, args.file_after, args.key, output_dir)


if __name__ == "__main__":
    main()

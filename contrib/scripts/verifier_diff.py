#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""
verifier_diff.py

Compares two eBPF verifier log files and visualizes the difference in
instruction counts per function between test runs.

Usage:
    python verifier_diff.py main.log patch.log
"""

import os
import re
import argparse
import shutil
import pandas as pd
import matplotlib.pyplot as plt
import datetime
import logging


def extract_verifier_data(log_content: str) -> dict[tuple[str, str], int]:
    """
    Extracts instruction counts per function from a verifier log.

    Args:
        log_content (str): Raw content of a verifier test log.

    Returns:
        dict[tuple[str, str], int]: Mapping of (test_name, function_name)
                                    to instruction count.
    """
    test_split_pattern = r"(=== RUN\s+TestVerifier/[^\n]+)"
    test_blocks = re.split(test_split_pattern, log_content)[1:]
    test_data = {}

    for i in range(0, len(test_blocks), 2):
        run_line = test_blocks[i].strip()
        test_name = run_line.replace("=== RUN   TestVerifier/", "")
        test_log = test_blocks[i + 1]

        matches = re.findall(
            r"verifier_test\.go:\d+: ([\w:]+): processed (\d+) insns", test_log
        )

        for func, insn in matches:
            test_data[(test_name, func)] = int(insn)

    return test_data


def compare_logs(file_before: str, file_after: str, output_dir: str) -> None:
    """
    Compares and stores instruction counts from two verifier logs into a CSV.

    Args:
        file_before (str): Path to the "before" verifier log.
        file_after (str): Path to the "after" verifier log.
        output_dir (str): Directory to save the resulting CSV file.

    Returns:
        None
    """
    with open(file_before) as f:
        log_before = f.read()
    with open(file_after) as f:
        log_after = f.read()

    data_before = extract_verifier_data(log_before)
    data_after = extract_verifier_data(log_after)

    all_keys = set(data_before.keys()).union(data_after.keys())
    diff_data = []

    for key in sorted(all_keys):
        has_before = key in data_before
        has_after = key in data_after

        if not has_before or not has_after:
            logging.warning("Entry {} missing in {}; skipping.".format(
                key, file_before if not has_before else file_after))
            continue

        insns_before = data_before[key]
        insns_after = data_after[key]
        insns_diff = insns_after - insns_before

        diff_data.append(
            [key[0], key[1], insns_before, insns_after, insns_diff])

    df = pd.DataFrame(diff_data, columns=[
        "Test", "Function", "Insns_Before", "Insns_After", "Insns_Diff"
    ])
    csv_path = os.path.join(output_dir, "insns_diff.csv")
    df.to_csv(csv_path, index=False)
    logging.info(f"Verifier instructions difference saved as CSV.")


def plot_insns_diff(output_dir: str) -> None:
    """
    Generates and saves horizontal bar plots showing instruction count delta.
    Functions with the same number of verified instructions are omitted.

    Args:
        output_dir (str): Output directory.

    Returns:
        None
    """
    df = pd.read_csv(os.path.join(output_dir, "insns_diff.csv"))

    df = df[df["Insns_Diff"] != 0]
    df = df[~((df["Insns_Before"] == 0) & (df["Insns_After"] == 0))]

    for test_name, test_df in df.groupby("Test"):
        plt.figure(figsize=(12, 8), constrained_layout=True)
        colors = test_df["Insns_Diff"].apply(
            lambda x: "green" if x > 0 else "red")
        bars = plt.barh(test_df["Function"],
                        test_df["Insns_Diff"], color=colors)

        for bar, insn_count in zip(bars, test_df["Insns_After"]):
            width = bar.get_width()
            xpos = width + 1 if width >= 0 else width - 1
            ha = "left" if width >= 0 else "right"
            plt.text(
                xpos,
                bar.get_y() + bar.get_height() / 2,
                f"({insn_count})",
                va="center",
                ha=ha,
                fontsize=8,
                color="black"
            )

        plt.xlabel("Verifier Instructions Difference (After - Before)\n"
                   "(Instructions After shown in brackets)")
        plt.ylabel("Function Name")
        plt.title(f"Program and Config: {test_name}")

        filename = test_name.replace("/", "_") + ".png"
        chart_path = os.path.join(output_dir, filename)
        plt.savefig(chart_path)
        plt.close()

        logging.info(f"Saved chart: {filename}.")

    logging.info(f"All charts successfully saved.")


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

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    output_dir = setup_output_dir(args.file_after, args.file_before)

    compare_logs(args.file_before, args.file_after, output_dir)
    plot_insns_diff(output_dir)


if __name__ == "__main__":
    main()

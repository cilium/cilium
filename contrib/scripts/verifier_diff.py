#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""
verifier_diff.py

Compares two eBPF verifier log files and compute statistics and plots between
the two runs. This script accepts two JSON files, `file1.json` and `file2.json`,
supposedly run before and after a code change, and creates an output directory
containing all the plots.
Running verifier tests locally would output a resulting JSON file under
`/tmp/verifier-complexity*/verifier-complexity.json`. As an alternative, these
JSON files can be obtained from CI runs.

Usage:
    python verifier_diff.py --help
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import os
import argparse
import shutil
import json
import numpy as np
import datetime
import logging
import multiprocessing
import pandas as pd

from pathlib import Path


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
        if key not in entry:
            logging.error(f"Key '{key}' not found in data.")
            break
        if not isinstance(entry[key], (int, float)) or not str(entry[key]).isnumeric():
            logging.error(f"Key '{key}' doesn't have a numeric value.")
            break
        k = (entry["collection"], entry["build"],
             entry["load"], entry["program"])
        organized[k] = int(entry[key])
    return organized


def _plot_group(collection: str, build: str, load: str, programs: str,
                vals1: list[float], vals2: list[float], key: str, outdir: str):
    """Plot comparison for a specific collection/build/load group.

    Args:
        collection (str): Collection name.
        build (str): Build identifier.
        load (str): Load identifier.
        programs (list[str]): List of program names.
        vals1 (list[float]): Values from the first file.
        vals2 (list[float]): Values from the second file.
        key (str): Key being compared.
        outdir (str): Output directory for the plot.
    """
    y_pos = np.arange(len(programs))
    bar_height = 0.35
    fig_width = 10
    fig_height = min(fig_width, max(fig_width // 2,
                                    bar_height * len(programs)))

    plt.figure(figsize=(fig_width, fig_height))
    bars1 = plt.barh(y_pos + bar_height / 2, vals1,
                           bar_height, label="File 1", alpha=0.7)
    bars2 = plt.barh(y_pos - bar_height / 2, vals2,
                          bar_height, label="File 2", alpha=0.7)

    plt.yticks(y_pos, programs)
    plt.xlabel(key)
    plt.title(f"Collection {collection} - Build {build} - Load {load}")
    plt.legend()

    max_val = max(vals1 + vals2)
    for bar in bars1:
        width = bar.get_width()
        plt.text(width + max_val * 0.01, bar.get_y() + bar.get_height() / 2,
                 f"{width}", va="center", ha="left", fontsize=8)

    for bar in bars2:
        width = bar.get_width()
        plt.text(width + max_val * 0.01, bar.get_y() + bar.get_height() / 2,
                 f"{width}", va="center", ha="left", fontsize=8)

    plt.tight_layout()
    collect_dir = os.path.join(outdir, collection)
    os.makedirs(collect_dir, exist_ok=True)
    outfile = os.path.join(collect_dir, f"states-build{build}-load{load}.png")
    plt.savefig(outfile)
    plt.close()
    logging.debug(f"Saved plot: {outfile}")


def plot_comparison(file1: str, file2: str, outdir: str, key: str, jobs: int):
    """Plot comparison of eBPF verifier logs.

    Args:
        file1 (str): Path to the first JSON file.
        file2 (str): Path to the second JSON file.
        outdir (str): Output directory for the plots.
        key (str): Key in the JSON to compare.
        jobs (int): Number of parallel processes to use.
    """
    outdir = os.path.join(outdir, "plots")
    os.makedirs(outdir, exist_ok=True)

    data1 = organize_data(load_json(file1), key)
    data2 = organize_data(load_json(file2), key)

    # Collect all unique (collection, build, load) triples
    groups = set((c, b, l) for c, b, l, _ in data1.keys()) | set(
        (c, b, l) for c, b, l, _ in data2.keys())

    tasks = []
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

        vals1 = []
        vals2 = []
        filtered_programs = []

        for prog in programs:
            v1 = data1.get((collection, build, load, prog), 0)
            v2 = data2.get((collection, build, load, prog), 0)
            if v1 == v2:
                logging.debug(
                    f"Program {prog} unchanged ({v1}) for "
                    f"collection {collection}, build {build}, "
                    f"load {load}, skipping.")
                continue
            filtered_programs.append(prog)
            vals1.append(v1)
            vals2.append(v2)

        if not filtered_programs:
            logging.debug(
                f"All programs unchanged for collection {collection} "
                f"build {build} load {load}, skipping.")
            continue

        tasks.append((collection, build, load, filtered_programs, vals1, vals2, key, outdir))

    if not tasks:
        logging.info(f"Skipping plots generation, all programs unchanged with {key=}.")
        return

    logging.info(f"Generating {len(tasks)} plots with {key=} ({jobs=}).")

    with multiprocessing.Pool(processes=jobs) as pool:
        pool.starmap(_plot_group, tasks)


def _store_stats_group(df: pd.DataFrame, output_file: str, fmt: str, key: str, groupby: list[str] = []):
    """Store comparison for a specific Dataframe.

    Args:
        df (pd.DataFrame): DataFrame to store.
        output_file (str): Output file path.
        fmt (str): Output format.
        key (str): Key in the JSON to compare.
        groupby (list[str], optional): Grouping columns. Defaults to [].
    """
    y = ['min', 'max', 'mean']
    df['diff'] = df['file2'] - df['file1']

    if groupby:
        output_file = os.path.join(output_file, f"groupby_{'_'.join(groupby)}.{fmt}")
        df = df.groupby(groupby)['diff'].describe(percentiles=[])
        df_nonzero = df[(df[y] != 0).any(axis=1)]
        df_nonzero.plot(kind='barh', y=y, figsize=(10, 0.15*len(df)), xlabel=key,
                title=f"Difference in {key} grouped by {tuple(groupby)}")
    else:
        output_file = os.path.join(output_file, f"all.{fmt}")
        df['diff'].describe(percentiles=[]).loc[y].plot(kind='barh', figsize=(10, 2), xlabel=key,
                                                        title=f"Overall difference in {key}")
    
    plt.tight_layout()
    plt.savefig(output_file.replace(f".{fmt}", ".png"))
    plt.close()

    if fmt == "csv":
        df.to_csv(output_file, index=bool(groupby))
    elif fmt == "json":
        df.to_json(output_file, orient="table", indent=2)
    else:
        logging.error(f"Unsupported format: {fmt}")

    logging.debug(f"Saved statistics {output_file} ({groupby=})")


def store_stats(file1: str, file2: str, outdir: str, key: str, fmt: str, jobs: int):
    """Store statistics of the differences between two sets of eBPF verifier logs.

    Args:
        file1 (str): Path to the first JSON file.
        file2 (str): Path to the second JSON file.
        outdir (str): Output directory for the statistics.
        key (str): Key in the JSON to compare.
        fmt (str): Output format for the statistics.
        jobs (int): Number of jobs processes to use.
    """
    outdir = os.path.join(outdir, "stats")
    os.makedirs(outdir, exist_ok=True)

    data1 = organize_data(load_json(file1), key)
    data2 = organize_data(load_json(file2), key)

    rows = []
    for collection, build, load, program in sorted(set(data1.keys()) | set(data2.keys())):
        v1 = data1.get((collection, build, load, program), 0)
        v2 = data2.get((collection, build, load, program), 0)
        if v1 == v2:
                logging.debug(
                    f"Program {program} unchanged for "
                    f"collection {collection}, build {build}, "
                    f"load {load}, skipping.")
                continue
        rows.append({
            "collection": collection,
            "build": build,
            "load": load,
            "program": program,
            "file1": v1,
            "file2": v2,
        })

    if not rows:
        logging.info(f"Skipping statistics generation, all programs unchanged with {key=}.")
        return

    df = pd.DataFrame(rows)
    tasks = [
        (df, outdir, fmt, key, []),
        (df, outdir, fmt, key, ["program"]),
        (df, outdir, fmt, key, ["program", "collection"])]
    
    logging.info(f"Generating {len(tasks)} statistics files with {key=} and different granularities ({jobs=})")
    
    with multiprocessing.Pool(processes=jobs) as pool:
        pool.starmap(_store_stats_group, tasks)


def setup_output_dir(file1: str, file2: str) -> str:
    """
    Generates a unique output directory and stores a copy of the log files used.

    Args:
        file1 (str): Path to the first JSON file.
        file2 (str): Path to the second JSON file.

    Returns:
        str: Name of the new output directory.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = f"verifier-diff-{timestamp}"

    logging.info(f"Creating output directory {output_dir} and backing up log files.")

    os.makedirs(output_dir, exist_ok=True)
    
    p1 = Path(file1)
    shutil.copy(file1, os.path.join(output_dir, f"file1-{p1.stem}{p1.suffix}"))
    
    p2 = Path(file2)
    shutil.copy(file2, os.path.join(output_dir, f"file2-{p2.stem}{p2.suffix}"))

    return output_dir


def main():
    """
    Entry point for the script. Parses arguments, sets up logging,
    and runs comparison and visualization.
    """
    parser = argparse.ArgumentParser(
        description="Compare number of verified instructions from eBPF verifier logs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("file1", type=str, help="Path to the first JSON file (i.e., before a patch).")
    parser.add_argument("file2", type=str, help="Path to the second JSON file (i.e., after a patch).")
    parser.add_argument('-v', '--verbose', action='store_true', help="Print debug logs.")
    parser.add_argument('-p', '--plot', action='store_true',
                        help="Generate plots for non-aggregated data.")
    parser.add_argument('-k', '--key', type=str, default="insns_processed",
                        choices=["insns_processed", "insns_limit",
                                 "max_states_per_insn", "total_states",
                                 "peak_states", "mark_read",  "stack_depth",
                                 "verification_time_microseconds"],
                        help="Verifier statistic to compare.")
    parser.add_argument('-j', '--jobs', type=int, default=multiprocessing.cpu_count(),
                        help="Number of jobs to run simultaneously.")
    parser.add_argument('--format', type=str, default="csv", choices=["csv", "json"],
                        help="Output format for statistics.")

    args = parser.parse_args()

    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    output_dir = setup_output_dir(args.file1, args.file2)

    store_stats(args.file1, args.file2, output_dir, args.key, args.format, args.jobs)

    if args.plot:
        plot_comparison(args.file1, args.file2, output_dir, args.key, args.jobs)


if __name__ == "__main__":
    main()

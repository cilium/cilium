#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""
Utility script to extract Grafana dashboard JSON files from monitoring-example.yaml ConfigMaps.

This script reads the monitoring-example.yaml file and extracts the dashboard
JSON content from ConfigMaps, saving them as separate JSON files for editing.
"""

import yaml
import sys
import os

def extract_and_save_dashboards(yaml_file_path, output_dir="."):
    """
    Extract dashboard JSON files from monitoring-example.yaml ConfigMaps.
    
    Args:
        yaml_file_path (str): Path to the monitoring-example.yaml file
        output_dir (str): Directory to save extracted JSON files
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        hubble_dashboard_json = None
        cilium_dashboard_json = None

        with open(yaml_file_path, 'r') as f:
            yaml_documents = yaml.safe_load_all(f)

            for doc in yaml_documents:
                if doc and doc.get('kind') == 'ConfigMap':
                    metadata_name = doc.get('metadata', {}).get('name')
                    if metadata_name == 'grafana-hubble-dashboard':
                        hubble_dashboard_json = doc.get('data', {}).get('hubble-dashboard.json')
                    elif metadata_name == 'grafana-cilium-dashboard':
                        cilium_dashboard_json = doc.get('data', {}).get('cilium-dashboard.json')

        success = True
        
        if hubble_dashboard_json:
            hubble_path = os.path.join(output_dir, 'hubble_dashboard.json')
            with open(hubble_path, 'w') as f_hubble:
                f_hubble.write(hubble_dashboard_json)
            print(f"Successfully extracted hubble dashboard to {hubble_path}")
        else:
            print("Could not find grafana-hubble-dashboard ConfigMap or its data.")
            success = False

        if cilium_dashboard_json:
            cilium_path = os.path.join(output_dir, 'cilium_dashboard.json')
            with open(cilium_path, 'w') as f_cilium:
                f_cilium.write(cilium_dashboard_json)
            print(f"Successfully extracted cilium dashboard to {cilium_path}")
        else:
            print("Could not find grafana-cilium-dashboard ConfigMap or its data.")
            success = False
        
        return success

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python extract_dashboards.py <yaml_file_path> [output_directory]")
        print("\nExample:")
        print("  python extract_dashboards.py ../monitoring-example.yaml")
        print("  python extract_dashboards.py ../monitoring-example.yaml /tmp/dashboards")
        sys.exit(1)
    
    yaml_file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) == 3 else "."
    
    # Validate input file exists
    if not os.path.exists(yaml_file_path):
        print(f"Error: Input file '{yaml_file_path}' not found", file=sys.stderr)
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    if not extract_and_save_dashboards(yaml_file_path, output_dir):
        sys.exit(1) 
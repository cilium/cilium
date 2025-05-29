#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""
Utility script to update Hubble dashboard content in monitoring-example.yaml ConfigMap.

This script reads a Grafana dashboard JSON file and updates the corresponding
ConfigMap entry in the monitoring-example.yaml file.
"""

import yaml
import sys
import os
import json

def update_monitoring_yaml(hubble_json_path, monitoring_yaml_path):
    """
    Update the Hubble dashboard ConfigMap in monitoring-example.yaml.
    
    Args:
        hubble_json_path (str): Path to the new Hubble dashboard JSON file
        monitoring_yaml_path (str): Path to the monitoring-example.yaml file
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Read the new Hubble dashboard content
        with open(hubble_json_path, 'r') as f_hubble:
            new_hubble_dashboard_content_str = f_hubble.read()

        # Load all documents from the monitoring YAML
        with open(monitoring_yaml_path, 'r') as f_monitoring:
            yaml_documents = list(yaml.safe_load_all(f_monitoring))

        found_configmap = False
        for doc in yaml_documents:
            if doc and isinstance(doc, dict) and doc.get('kind') == 'ConfigMap':
                metadata = doc.get('metadata', {})
                if metadata.get('name') == 'grafana-hubble-dashboard':
                    if 'data' not in doc or doc['data'] is None:
                        doc['data'] = {}
                    doc['data']['hubble-dashboard.json'] = new_hubble_dashboard_content_str
                    found_configmap = True
                    break
        
        if not found_configmap:
            print(f"Error: ConfigMap 'grafana-hubble-dashboard' not found in {monitoring_yaml_path}", file=sys.stderr)
            return False

        # Write the updated documents back to the monitoring YAML
        with open(monitoring_yaml_path, 'w') as f_monitoring:
            yaml.dump_all(yaml_documents, f_monitoring, sort_keys=False, default_flow_style=None)
        
        print(f"Successfully updated '{monitoring_yaml_path}' with new Hubble dashboard content.")
        return True

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return False

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python update_yaml_configmap.py <path_to_hubble_dashboard.json> <path_to_monitoring_example.yaml>")
        print("\nExample:")
        print("  python update_yaml_configmap.py ../files/grafana-dashboards/hubble-dashboard.json ../monitoring-example.yaml")
        sys.exit(1)
    
    hubble_json_file = sys.argv[1]
    monitoring_yaml_file = sys.argv[2]
    
    # Validate input files exist
    if not os.path.exists(hubble_json_file):
        print(f"Error: Input file '{hubble_json_file}' not found", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(monitoring_yaml_file):
        print(f"Error: Input file '{monitoring_yaml_file}' not found", file=sys.stderr)
        sys.exit(1)
    
    if not update_monitoring_yaml(hubble_json_file, monitoring_yaml_file):
        sys.exit(1) 
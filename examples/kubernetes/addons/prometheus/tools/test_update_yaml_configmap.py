#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for update_yaml_configmap.py

Test the functionality of updating Hubble dashboard content in monitoring YAML files.
"""

import unittest
import tempfile
import os
import sys
from update_yaml_configmap import update_monitoring_yaml

class TestUpdateYamlConfigMap(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures with sample YAML and JSON content."""
        self.sample_yaml_content = """---
apiVersion: v1
kind: Namespace
metadata: {name: cilium-monitoring}
---
apiVersion: v1
kind: ConfigMap
metadata:
  labels: {app: grafana}
  name: grafana-hubble-dashboard
  namespace: cilium-monitoring
data: 
  hubble-dashboard.json: |
    {"old": "dashboard", "version": 1}
---
apiVersion: v1
kind: ConfigMap
metadata:
  labels: {app: grafana}
  name: grafana-other-dashboard
  namespace: cilium-monitoring
data: 
  other-dashboard.json: |
    {"other": "dashboard"}
"""
        
        self.sample_json_content = '{"new": "dashboard", "version": 2, "enhanced": true}'

    def test_update_existing_configmap(self):
        """Test updating an existing ConfigMap with new dashboard content."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as yaml_file:
            yaml_file.write(self.sample_yaml_content)
            yaml_file_path = yaml_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as json_file:
            json_file.write(self.sample_json_content)
            json_file_path = json_file.name

        try:
            # Test the update function
            result = update_monitoring_yaml(json_file_path, yaml_file_path)
            self.assertTrue(result, "update_monitoring_yaml should return True on success")

            # Verify the content was updated
            with open(yaml_file_path, 'r') as f:
                updated_content = f.read()
            
            self.assertIn('"new": "dashboard"', updated_content, "New dashboard content should be present")
            self.assertIn('"enhanced": true', updated_content, "Enhanced features should be present")
            self.assertNotIn('"old": "dashboard"', updated_content, "Old dashboard content should be replaced")

        finally:
            # Cleanup
            os.unlink(yaml_file_path)
            os.unlink(json_file_path)

    def test_missing_configmap(self):
        """Test behavior when the target ConfigMap doesn't exist."""
        yaml_content_no_hubble = """---
apiVersion: v1
kind: Namespace
metadata: {name: cilium-monitoring}
---
apiVersion: v1
kind: ConfigMap
metadata:
  labels: {app: grafana}
  name: grafana-other-dashboard
  namespace: cilium-monitoring
data: 
  other-dashboard.json: |
    {"other": "dashboard"}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as yaml_file:
            yaml_file.write(yaml_content_no_hubble)
            yaml_file_path = yaml_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as json_file:
            json_file.write(self.sample_json_content)
            json_file_path = json_file.name

        try:
            # Test the update function - should fail
            result = update_monitoring_yaml(json_file_path, yaml_file_path)
            self.assertFalse(result, "update_monitoring_yaml should return False when ConfigMap not found")

        finally:
            # Cleanup
            os.unlink(yaml_file_path)
            os.unlink(json_file_path)

    def test_missing_input_files(self):
        """Test behavior with missing input files."""
        # Test with non-existent JSON file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as yaml_file:
            yaml_file.write(self.sample_yaml_content)
            yaml_file_path = yaml_file.name

        try:
            result = update_monitoring_yaml("/nonexistent/file.json", yaml_file_path)
            self.assertFalse(result, "Should return False for non-existent JSON file")

            # Test with non-existent YAML file
            result = update_monitoring_yaml(yaml_file_path, "/nonexistent/file.yaml")
            self.assertFalse(result, "Should return False for non-existent YAML file")

        finally:
            os.unlink(yaml_file_path)

    def test_configmap_without_data_section(self):
        """Test updating a ConfigMap that has no data section."""
        yaml_content_no_data = """---
apiVersion: v1
kind: ConfigMap
metadata:
  labels: {app: grafana}
  name: grafana-hubble-dashboard
  namespace: cilium-monitoring
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as yaml_file:
            yaml_file.write(yaml_content_no_data)
            yaml_file_path = yaml_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as json_file:
            json_file.write(self.sample_json_content)
            json_file_path = json_file.name

        try:
            # Test the update function
            result = update_monitoring_yaml(json_file_path, yaml_file_path)
            self.assertTrue(result, "Should successfully add data section to ConfigMap")

            # Verify the content was added
            with open(yaml_file_path, 'r') as f:
                updated_content = f.read()
            
            self.assertIn('"new": "dashboard"', updated_content, "New dashboard content should be present")

        finally:
            # Cleanup
            os.unlink(yaml_file_path)
            os.unlink(json_file_path)

if __name__ == '__main__':
    unittest.main() 
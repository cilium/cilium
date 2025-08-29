# Grafana Dashboard Management Tools

This directory contains utilities for managing Grafana dashboards in the Cilium monitoring stack.

## Overview

These tools help developers and maintainers work with Grafana dashboards that are embedded as JSON content within Kubernetes ConfigMaps in the `monitoring-example.yaml` file.

## Tools

### 1. `extract_dashboards.py`
Extracts dashboard JSON files from the monitoring-example.yaml ConfigMaps.

**Usage:**
```bash
python extract_dashboards.py ../monitoring-example.yaml [output_directory]
```

**Example:**
```bash
python extract_dashboards.py ../monitoring-example.yaml /tmp/dashboards
```

### 2. `update_yaml_configmap.py`
Updates the Hubble dashboard ConfigMap with new JSON content.

**Usage:**
```bash
python update_yaml_configmap.py <hubble_dashboard.json> <monitoring-example.yaml>
```

**Example:**
```bash
python update_yaml_configmap.py hubble_dashboard.json ../monitoring-example.yaml
```

### 3. `test_update_yaml_configmap.py`
Unit tests for the update utility.

**Usage:**
```bash
python test_update_yaml_configmap.py
```

## Makefile Commands

The included `Makefile` provides convenient commands for common tasks:

```bash
# Show available commands
make help

# Extract dashboard JSON files for editing
make extract-dashboards

# Update Hubble dashboard from a JSON file
make update-hubble HUBBLE_JSON=path/to/hubble-dashboard.json

# Run unit tests
make test

# Validate YAML syntax
make validate-yaml

# Clean up temporary files
make clean

# Development workflow (extract -> edit -> update)
make dev-workflow
```

## Development Workflow

### Typical workflow for updating dashboards:

1. **Extract current dashboards:**
   ```bash
   make extract-dashboards
   ```
   This creates JSON files in `/tmp/cilium-dashboards/`

2. **Edit the dashboard:**
   - Open `/tmp/cilium-dashboards/hubble_dashboard.json` in your editor
   - Make your changes to the dashboard configuration
   - Test the dashboard in Grafana if possible

3. **Update the monitoring configuration:**
   ```bash
   make update-hubble HUBBLE_JSON=/tmp/cilium-dashboards/hubble_dashboard.json
   ```
   Or use the shortcut:
   ```bash
   make update-hubble-extracted
   ```

4. **Validate the changes:**
   ```bash
   make validate-yaml
   make test
   ```

## Dashboard Structure

The tools work with these ConfigMaps in `monitoring-example.yaml`:

- **`grafana-hubble-dashboard`**: Contains the Hubble observability dashboard
- **`grafana-cilium-dashboard`**: Contains the main Cilium metrics dashboard

Each ConfigMap has a `data` section with a JSON key containing the Grafana dashboard definition.

## Requirements

- Python 3.6+
- PyYAML library (`pip install PyYAML`)

## Testing

The tools include comprehensive unit tests:

```bash
# Run all tests
make test

# Run tests with verbose output
python test_update_yaml_configmap.py -v
```

## Contributing

When modifying these tools:

1. Update the unit tests for any new functionality
2. Test with real dashboard JSON files
3. Ensure the Makefile commands work correctly
4. Update this README if adding new features

## Background

These tools were created to support the enhancement of Cilium's Grafana dashboards, particularly the addition of service graph capabilities and eBPF drop statistics to the Hubble dashboard. They provide a clean way to manage dashboard configurations without cluttering the main repository with temporary JSON files. 
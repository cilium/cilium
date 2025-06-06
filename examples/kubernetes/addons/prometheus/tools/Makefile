# Makefile for managing Grafana dashboards in monitoring-example.yaml
#
# This Makefile provides utilities for extracting, updating, and testing
# Grafana dashboard configurations within the Prometheus monitoring example.

MONITORING_YAML := ../monitoring-example.yaml
DASHBOARDS_DIR := ../files/grafana-dashboards
TEMP_DIR := /tmp/cilium-dashboards

# Python executable
PYTHON := python3

# Default target
.PHONY: help
help:
	@echo "Grafana Dashboard Management Tools"
	@echo "=================================="
	@echo ""
	@echo "Available targets:"
	@echo "  extract-dashboards    Extract dashboard JSON files from monitoring-example.yaml"
	@echo "  update-hubble        Update Hubble dashboard in monitoring-example.yaml"
	@echo "  test                 Run unit tests for the tools"
	@echo "  clean                Clean up temporary files"
	@echo "  validate-yaml        Validate the monitoring-example.yaml syntax"
	@echo ""
	@echo "Usage examples:"
	@echo "  make extract-dashboards"
	@echo "  make update-hubble HUBBLE_JSON=path/to/new/hubble-dashboard.json"
	@echo "  make test"

# Extract dashboard JSON files from the monitoring YAML
.PHONY: extract-dashboards
extract-dashboards:
	@echo "Extracting dashboards from $(MONITORING_YAML)..."
	@mkdir -p $(TEMP_DIR)
	$(PYTHON) extract_dashboards.py $(MONITORING_YAML) $(TEMP_DIR)
	@echo "Dashboard JSON files extracted to $(TEMP_DIR)/"
	@echo "  - hubble_dashboard.json"
	@echo "  - cilium_dashboard.json"

# Update Hubble dashboard in monitoring YAML
.PHONY: update-hubble
update-hubble:
ifndef HUBBLE_JSON
	@echo "Error: HUBBLE_JSON variable must be set"
	@echo "Usage: make update-hubble HUBBLE_JSON=path/to/hubble-dashboard.json"
	@exit 1
endif
	@echo "Updating Hubble dashboard in $(MONITORING_YAML)..."
	@echo "Using dashboard file: $(HUBBLE_JSON)"
	$(PYTHON) update_yaml_configmap.py $(HUBBLE_JSON) $(MONITORING_YAML)
	@echo "Hubble dashboard updated successfully!"

# Update Hubble dashboard using extracted file
.PHONY: update-hubble-extracted
update-hubble-extracted: extract-dashboards
	@echo "Updating Hubble dashboard using extracted file..."
	$(PYTHON) update_yaml_configmap.py $(TEMP_DIR)/hubble_dashboard.json $(MONITORING_YAML)
	@echo "Hubble dashboard updated from extracted file!"

# Run unit tests
.PHONY: test
test:
	@echo "Running unit tests..."
	$(PYTHON) test_update_yaml_configmap.py -v

# Validate YAML syntax
.PHONY: validate-yaml
validate-yaml:
	@echo "Validating $(MONITORING_YAML) syntax..."
	@$(PYTHON) -c "import yaml; yaml.safe_load_all(open('$(MONITORING_YAML)', 'r'))" && echo "✓ YAML syntax is valid"

# Clean up temporary files
.PHONY: clean
clean:
	@echo "Cleaning up temporary files..."
	@rm -rf $(TEMP_DIR)
	@rm -rf __pycache__
	@rm -f *.pyc
	@echo "Cleanup complete!"

# Make scripts executable
.PHONY: setup
setup:
	@echo "Setting up dashboard management tools..."
	@chmod +x *.py
	@echo "Tools are ready to use!"

# Development workflow: extract -> edit -> update
.PHONY: dev-workflow
dev-workflow:
	@echo "Starting development workflow..."
	@echo "1. Extracting current dashboards..."
	@$(MAKE) extract-dashboards
	@echo ""
	@echo "2. Dashboard JSON files are now in $(TEMP_DIR)/"
	@echo "   Edit hubble_dashboard.json as needed"
	@echo ""
	@echo "3. When ready, run: make update-hubble-extracted"

# Show current dashboard info
.PHONY: info
info:
	@echo "Dashboard Management Tools Information"
	@echo "===================================="
	@echo "Monitoring YAML: $(MONITORING_YAML)"
	@echo "Dashboards Dir:  $(DASHBOARDS_DIR)"
	@echo "Temp Directory:  $(TEMP_DIR)"
	@echo "Python:          $(PYTHON)"
	@echo ""
	@echo "Current dashboard ConfigMaps in $(MONITORING_YAML):"
	@grep -A 2 "name: grafana.*dashboard" $(MONITORING_YAML) || echo "  (none found)" 
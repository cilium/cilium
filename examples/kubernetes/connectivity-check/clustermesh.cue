package connectivity_check

// Add support for global namespace annotations in connectivity tests
// This extends the base connectivity check with clustermesh global namespace support

_globalNamespaceAnnotation: "clustermesh.cilium.io/global": "true"

// Extend deployment metadata to include global namespace support when clustermesh is enabled
deployment: [ID=_]: {
	// Add global namespace annotation if clustermesh testing is enabled
	if _clustermeshEnabled {
		metadata: {
			namespace: *"default" | string
			annotations: _globalNamespaceAnnotation
		}
	}
}

// Configuration for clustermesh global namespace testing
_clustermeshEnabled: *false | bool @tag(clustermesh)

// Test namespace configurations for clustermesh
testNamespaces: {
	if _clustermeshEnabled {
		// Global namespace for clustermesh tests
		"cilium-test-global": {
			apiVersion: "v1"
			kind: "Namespace"
			metadata: {
				name: "cilium-test-global"
				annotations: _globalNamespaceAnnotation
			}
		}
		
		// Local namespace for clustermesh tests (no annotation)
		"cilium-test-local": {
			apiVersion: "v1"
			kind: "Namespace"
			metadata: {
				name: "cilium-test-local"
			}
		}
	}
}

// Extend services for global services testing
service: [ID=_]: {
	if _clustermeshEnabled && ID =~ ".*global.*" {
		metadata: annotations: {
			"service.cilium.io/global": "true"
		}
	}
}
// add-image-digests updates defaults/imagedigests.json.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var pathsByGroup = map[string][]string{
	"cilium": {
		"quay.io/cilium/cilium",
		"quay.io/cilium/clustermesh-apiserver",
		"quay.io/cilium/hubble-relay",
		"quay.io/cilium/operator-aws",
		"quay.io/cilium/operator-azure",
		"quay.io/cilium/operator-generic",
	},
	"hubble-ui": {
		"quay.io/cilium/hubble-ui",
		"quay.io/cilium/hubble-ui-backend",
	},
}

var digestRegexp = regexp.MustCompile(`^Digest:\s+(sha256:[0-9a-f]{64})$`)

// getImageDigest returns the digest of image.
//
// FIXME there must be an easier way to get the image digest than pulling the
// image and parsing the output of docker pull.
func getImageDigest(image string) (string, error) {
	cmd := exec.Command("docker", "pull", image)
	fmt.Printf("🚀 running %s\n", strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(output), "\n") {
		if m := digestRegexp.FindStringSubmatch(line); m != nil {
			digest := m[1]
			fmt.Printf("🔍 found %s for %s\n", digest, image)
			return digest, nil
		}
	}

	return "", fmt.Errorf("digest not found for %s", image)
}

func run() error {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		return fmt.Errorf("usage: %s cilium|hubble-ui <tag> [filename]", os.Args[0])
	}

	paths, ok := pathsByGroup[os.Args[1]]
	if !ok {
		return fmt.Errorf("unknown group %s", os.Args[1])
	}
	tag := os.Args[2]
	filename := "defaults/imagedigests.json"
	if len(os.Args) > 3 {
		filename = os.Args[3]
	}

	fmt.Printf("📖 reading %s\n", filename)
	imageDigestsJSON, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	pathTagDigests := make(map[string]map[string]string)
	if err := json.Unmarshal(imageDigestsJSON, &pathTagDigests); err != nil {
		return err
	}

	addedDigest := false
	for _, path := range paths {
		if _, ok := pathTagDigests[path][tag]; ok {
			continue
		}
		digest, err := getImageDigest(path + ":" + tag)
		if err != nil {
			return err
		}
		if pathTagDigests[path] == nil {
			pathTagDigests[path] = make(map[string]string)
		}
		pathTagDigests[path][tag] = "@" + digest
		addedDigest = true
	}

	if !addedDigest {
		fmt.Println("✅ everything is up to date")
		return nil
	}

	fmt.Printf("💾 writing %s\n", filename)
	imageDigestsJSON, err = json.MarshalIndent(pathTagDigests, "", "  ")
	if err != nil {
		return err
	}
	//nolint:gosec
	if err := os.WriteFile(filename, imageDigestsJSON, 0o644); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Printf("😢 %s\n", err.Error())
		os.Exit(1)
	}
}

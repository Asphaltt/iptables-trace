package main

import (
	"fmt"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/shirou/gopsutil/v3/host"
)

func isKernelVersionGte_5_16() (bool, error) {
	release, err := host.KernelVersion()
	if err != nil {
		return false, fmt.Errorf("failed to get kernel version: %v", err)
	}

	version, err := semver.Make(extractVersion(release))
	if err != nil {
		return false, fmt.Errorf("failed to parse kernel version: %v", err)
	}

	version_5_16 := semver.MustParse("5.16.0")

	return version.GTE(version_5_16), nil
}

func extractVersion(release string) string {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 3 {
		return release
	}

	patch := parts[2]

	// Find the first non-digit character
	for i, c := range patch {
		if c < '0' || c > '9' {
			patch = patch[:i]
			break
		}
	}

	parts[2] = patch
	return strings.Join(parts, ".")
}

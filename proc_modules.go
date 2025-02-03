package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const procModulesFile = "/proc/modules"

const (
	kernelModuleIpTables = "ip_tables"
	kernelModuleNfTables = "nf_tables"
)

type procModuleInfo struct{}

func readProcModules() (map[string]procModuleInfo, error) {
	fd, err := os.Open(procModulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", procModulesFile, err)
	}
	defer fd.Close()

	modules := make(map[string]procModuleInfo)
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 {
			modules[fields[0]] = procModuleInfo{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", procModulesFile, err)
	}

	return modules, nil
}

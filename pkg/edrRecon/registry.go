package edrRecon

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

var (
	outputLock sync.Mutex
	paramWg    sync.WaitGroup
	output     []string
)

func runCMDCommand(ctx context.Context, command string) ([]byte, error) {
	params := []string{"/c", command}
	cmd, err := makeCmd(ctx, params...)
	if err != nil {
		return nil, err
	}
	return cmd.CombinedOutput()
}

func makeCmd(ctx context.Context, param ...string) (*exec.Cmd, error) {
	path, err := exec.LookPath("cmd")
	if err != nil {
		return nil, err
	}
	var cmdline string
	for _, s := range param {
		cmdline += s + " "
	}
	cmdline = strings.TrimSpace(cmdline)
	cmd := exec.CommandContext(ctx, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdline}
	return cmd, nil
}

func EnumRegistry() []string {
	ctx := context.Background()
	for _, x := range RegistrySearchList {
		paramWg.Add(1)
		go func(args string) {
			defer paramWg.Done()
			stdout, err := runCMDCommand(ctx, args)
			if err != nil {
				return
			}
			outputLock.Lock()
			defer outputLock.Unlock()
			if len(stdout) != 0 {
				output = append(output, string(stdout))
			}
		}(x)
	}
	paramWg.Wait()
	return output
}

func (edr *EdrHunt) CheckRegistry() (RegistryMetaData, error) {

	output := strings.Join(EnumRegistry(), " ")
	var analysis RegistryMetaData
	// matches = append(matches, "Scanning Registry:")
	if output != "" {
		processedOutput := strings.ToLower(output)
		for _, match := range RegistryReconList {
			if strings.Contains(
				processedOutput,
				strings.ToLower(match)) {
				analysis.ScanMatch = append(analysis.ScanMatch, match)
			}
		}
	}
	if cap(analysis.ScanMatch) > 0 {
		return analysis, nil
	}
	return RegistryMetaData{}, fmt.Errorf("nothing found in registry")
}

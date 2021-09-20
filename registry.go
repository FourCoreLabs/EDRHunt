package edrRecon

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
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
	var outputLock sync.Mutex
	var paramWg sync.WaitGroup
	var params, output []string
	params = append(params,
		`reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"`,
		`reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS"`,
		`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		`reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA"`,
		`reg query "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard"`,
		`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"`,
		`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"`,
		`reg query HKLM\Software\McAfee\Endpoint\AV`,
		`reg query HKLM\Software\Symantec`,
		`reg query HKLM\Software\Cylance\Desktop`,
		`reg query HKLM\Software\CbDefense`,
		`reg query HKLM\Software\CrowdStrike\InfDb`,
		`reg query "HKLM\Software\Sentinel Labs"`,
		`reg query "HKLM\Software\Sentinel Labs\Agent"`)

	ctx := context.Background()
	for x := range params {
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
		}(params[x])
	}
	paramWg.Wait()
	return output
}

func (edr *EdrHunt) CheckRegistry() (string, error) {
	output := strings.Join(EnumRegistry(), " ")
	var matches []string
	matches = append(matches, "Scanning Registry:")
	if output != "" {
		processedOutput := strings.ToLower(output)

		for _, match := range RegistryReconList {
			if strings.Contains(
				processedOutput,
				strings.ToLower(match)) {
				matches = append(matches, fmt.Sprintf("\n\t%s", match))
			}
		}
	}
	if cap(matches) > 1 {
		return fmt.Sprint(strings.Join(matches, "")), nil
	}
	return "", fmt.Errorf("nothing found in registry")
}

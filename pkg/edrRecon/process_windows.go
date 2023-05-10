package edrRecon

import (
	"fmt"
	"strings"

	"github.com/fourcorelabs/edrhunt/pkg/resources"
	"github.com/hashicorp/go-multierror"
	"github.com/yusufpapurcu/wmi"
)

type Win32_Process struct {
	Name            string
	ExecutablePath  string
	Description     string
	Caption         string
	CommandLine     string
	ProcessId       uint32
	ParentProcessId uint32

	// Status    string
	// StartMode string
}

// CheckProcesses returns a list of processes matching any suspicious running process names present in edrdata.go.
func CheckProcesses() ([]resources.ProcessMetaData, error) {
	var (
		processList []Win32_Process
		multiErr    error
		summary     []resources.ProcessMetaData = make([]resources.ProcessMetaData, 0)
	)

	query := wmi.CreateQuery(&processList, "")

	if err := wmi.Query(query, &processList); err != nil {
		return summary, err
	}

	for _, process := range processList {
		if process.Name == "" {
			continue
		}

		output, err := AnalyzeProcess(process)
		if err != nil {
			multiErr = multierror.Append(multiErr, err)
			continue
		}

		if len(output.ScanMatch) > 0 {
			summary = append(summary, output)
		}
	}

	return summary, multiErr
}

func AnalyzeProcess(process Win32_Process) (resources.ProcessMetaData, error) {
	analysis := resources.ProcessMetaData{
		ProcessName:        process.Name,
		ProcessPath:        process.ExecutablePath,
		ProcessDescription: process.Description,
		ProcessCaption:     process.Caption,
		ProcessCmdLine:     process.CommandLine,
		ProcessPID:         fmt.Sprint(process.ProcessId),
		ProcessParentPID:   fmt.Sprint(process.ParentProcessId),
	}

	if analysis.ProcessPath != "" {
		analysis.ProcessExeMetaData, _ = GetFileMetaData(analysis.ProcessPath)
	}

	for _, edr := range EdrList {
		if strings.Contains(
			strings.ToLower(fmt.Sprint(analysis)),
			strings.ToLower(edr)) {
			analysis.ScanMatch = append(analysis.ScanMatch, edr)
		}
	}

	return analysis, nil
}

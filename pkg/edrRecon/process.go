package edrRecon

import (
	"fmt"
	"strings"

	"github.com/StackExchange/wmi"
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
func CheckProcesses() ([]ProcessMetaData, error) {
	var (
		processList []Win32_Process
		errArray    []string
		summary     []ProcessMetaData
	)
	query := wmi.CreateQuery(&processList, "")
	err := wmi.Query(query, &processList)
	if err != nil {
		return []ProcessMetaData{}, err
	}
	for _, process := range processList {
		output, err := AnalyzeProcess(process)
		if err != nil {
			errArray = append(errArray, fmt.Sprintf("%v", err))
		}
		if output.ProcessName == "" {
			continue
		}
		summary = append(summary, output)
	}

	return summary, fmt.Errorf("%v", errArray)
}

func AnalyzeProcess(process Win32_Process) (ProcessMetaData, error) {
	var err error
	analysis := ProcessMetaData{
		ProcessName:        process.Name,
		ProcessPath:        process.ExecutablePath,
		ProcessDescription: process.Description,
		ProcessCaption:     process.Caption,
		ProcessCmdLine:     process.CommandLine,
		ProcessPID:         fmt.Sprint(process.ProcessId),
		ProcessParentPID:   fmt.Sprint(process.ParentProcessId),
	}

	if analysis.ProcessPath != "" {
		analysis.ProcessExeMetaData, err = GetFileMetaData(analysis.ProcessPath)
	}

	for _, edr := range EdrList {
		if strings.Contains(
			strings.ToLower(fmt.Sprint(analysis)),
			strings.ToLower(edr)) {
			analysis.ScanMatch = append(analysis.ScanMatch, edr)
		}
	}

	if len(analysis.ScanMatch) > 0 {
		return analysis, err
	}
	return ProcessMetaData{}, err
}

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

func (edr *EdrHunt) CheckProcesses() (string, error) {
	var (
		processList []Win32_Process
		summary     string
		errArray    []string
	)
	query := wmi.CreateQuery(&processList, "")
	err := wmi.Query(query, &processList)
	if err != nil {
		return "", err
	}
	for _, process := range processList {
		output, err := AnalyzeProcess(process)
		if err != nil {
			errArray = append(errArray, fmt.Sprintf("%v", err))
		}
		summary += output
	}

	return summary, fmt.Errorf("%v", errArray)
}

func AnalyzeProcess(process Win32_Process) (string, error) {
	processName := process.Name
	processPath := process.ExecutablePath
	processDescription := process.Description
	processCaption := process.Caption
	processCmdLine := process.CommandLine
	processPID := fmt.Sprint(process.ProcessId)
	processParent := fmt.Sprint(process.ParentProcessId)
	var (
		metadata string
		err      error
		matches  []string
	)
	allAttribs := fmt.Sprintf("%s %s %s %s %s", processName, processPath, processDescription, processCaption, processCmdLine)
	if processPath != "" {
		metadata, err = GetFileMetaData(processPath)
		allAttribs += metadata
	}
	for _, edr := range EdrList {
		//regexp as alternate but saving another import. No bully Pt.2
		if strings.Contains(
			strings.ToLower(allAttribs),
			strings.ToLower(edr)) {
			matches = append(matches, edr)
		}
	}
	if cap(matches) > 0 {
		output := fmt.Sprintf("\nSuspicious Process Name: %s\nDescription: %s\nCaption: %s\nBinary: %s\nProcessID: %s\nParent Process: %s\nProcess CmdLine : %s\nFile Metadata: %s\nMatched Keyword: %s\n", processName, processDescription, processCaption, processPath, processPID, processParent, processCmdLine, metadata, matches)
		return output, err
	}
	return "", err
}

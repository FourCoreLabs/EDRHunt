package edrRecon

import (
	"fmt"
	"strings"

	"github.com/StackExchange/wmi"
)

type Win32_Service struct {
	Name        string
	DisplayName string
	Description string
	Caption     string
	PathName    string
	State       string
	ProcessId   uint32
	// Status    string
	// StartMode string
}

func (edr *EdrHunt) CheckServices() (string, error) {
	var (
		serviceList []Win32_Service
		summary     string
		errArray    []string
	)
	query := wmi.CreateQuery(&serviceList, "")
	err := wmi.Query(query, &serviceList)
	if err != nil {
		return "", err
	}
	for _, service := range serviceList {
		output, err := AnalyzeService(service)
		if err != nil {
			errArray = append(errArray, fmt.Sprintf("%v", err))
		}
		summary += output
	}

	return summary, fmt.Errorf("%v", errArray)
}

func AnalyzeService(service Win32_Service) (string, error) {
	serviceName := service.Name
	serviceDisplayName := service.DisplayName
	serviceDescription := service.Description
	serviceCaption := service.Caption
	servicePathName := service.PathName
	serviceState := service.State
	serviceProcessId := fmt.Sprint(service.ProcessId)
	var (
		metadata string
		err      error
		matches  []string
	)
	allAttribs := fmt.Sprintf("%s %s %s %s %s", serviceName, serviceDisplayName, serviceDescription, serviceCaption, servicePathName)
	if servicePathName != "" {
		trim := strings.Index(servicePathName, ".exe")
		if trim > 0 {
			servicePath := servicePathName[:trim] + ".exe"
			metadata, err = GetFileMetaData(servicePath)
			allAttribs += metadata
		}
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
		output := fmt.Sprintf("\nSuspicious Service Name: %s\nDisplay Name: %s\nDescription: %s\nCaption: %s\nCommandLine: %s\nStatus: %s\nProcessID: %s\nFile Metadata: %s\nMatched Keyword: %s\n", serviceName, serviceDisplayName, serviceDescription, serviceCaption, servicePathName, serviceState, serviceProcessId, metadata, matches)
		return output, err
	}
	return "", err
}

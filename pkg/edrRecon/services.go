package edrRecon

import (
	"fmt"
	"strings"

	"github.com/StackExchange/wmi"
	"github.com/hashicorp/go-multierror"
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

// CheckServices return a list of installed services matching any suspicious service names present in edrdata.go.
func CheckServices() ([]ServiceMetaData, error) {
	var (
		serviceList []Win32_Service
		multiErr    error
		summary     []ServiceMetaData
	)

	query := wmi.CreateQuery(&serviceList, "")

	if err := wmi.Query(query, &serviceList); err != nil {
		return summary, err
	}

	for _, service := range serviceList {
		if service.Name == "" {
			continue
		}

		output, err := AnalyzeService(service)
		if err != nil {
			multiErr = multierror.Append(multiErr, err)
		}

		if len(output.ScanMatch) > 0 {
			summary = append(summary, output)
		}
	}

	return summary, multiErr
}

func AnalyzeService(service Win32_Service) (ServiceMetaData, error) {
	analysis := ServiceMetaData{
		ServiceName:        service.Name,
		ServiceDisplayName: service.DisplayName,
		ServiceDescription: service.Description,
		ServiceCaption:     service.Caption,
		ServicePathName:    service.PathName,
		ServiceState:       service.State,
		ServiceProcessId:   fmt.Sprint(service.ProcessId),
	}

	if analysis.ServicePathName != "" {
		trim := strings.Index(analysis.ServicePathName, ".exe")
		if trim > 0 {
			servicePath := analysis.ServicePathName[:trim] + ".exe"
			analysis.ServiceExeMetaData, _ = GetFileMetaData(servicePath)
		}
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

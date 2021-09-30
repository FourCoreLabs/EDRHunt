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

func (edr *EdrHunt) CheckServices() ([]ServiceMetaData, error) {
	var (
		serviceList []Win32_Service
		errArray    []string
		summary     []ServiceMetaData
	)
	query := wmi.CreateQuery(&serviceList, "")
	err := wmi.Query(query, &serviceList)
	if err != nil {
		return []ServiceMetaData{}, err
	}
	for _, service := range serviceList {
		output, err := AnalyzeService(service)
		if err != nil {
			errArray = append(errArray, fmt.Sprintf("%v", err))
		}
		if output.ServiceName == "" {
			continue
		}
		summary = append(summary, output)
	}

	return summary, fmt.Errorf("%v", errArray)
}

func AnalyzeService(service Win32_Service) (ServiceMetaData, error) {

	var err error
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
			analysis.ServiceExeMetaData, err = GetFileMetaData(servicePath)
		}
	}

	for _, edr := range EdrList {
		if strings.Contains(
			strings.ToLower(fmt.Sprint(analysis)),
			strings.ToLower(edr)) {
			analysis.ScanMatch = append(analysis.ScanMatch, edr)
		}
	}
	if cap(analysis.ScanMatch) > 0 {
		return analysis, err
	}
	return ServiceMetaData{}, err
}

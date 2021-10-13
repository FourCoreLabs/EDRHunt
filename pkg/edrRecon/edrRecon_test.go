package edrRecon

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCheckDrivers(t *testing.T) {

	summary, err := CheckDrivers()
	for _, driver := range summary {
		output := fmt.Sprintf("\nSuspicious Driver Module: %s\nDriver FilePath: %s\nDriver File Metadata: %s\nMatched Keyword: %s\n", driver.DriverBaseName, driver.DriverFilePath, FileMetaDataParser(driver.DriverSysMetaData), driver.ScanMatch)
		fmt.Println(output)
	}
	if err.Error() != "" {
		t.Error(err)
	}
}

func TestCheckRegistry(t *testing.T) {
	summary, err := CheckRegistry(context.TODO())
	fmt.Println("Scanning registry: ")
	for _, match := range summary.ScanMatch {
		fmt.Printf("\t%s\n", match)
	}

	if err != nil {
		fmt.Println("error", err)
	}
}

func TestCheckServices(t *testing.T) {
	summary, err := CheckServices()
	for _, service := range summary {
		output := fmt.Sprintf("\nSuspicious Service Name: %s\nDisplay Name: %s\nDescription: %s\nCaption: %s\nCommandLine: %s\nStatus: %s\nProcessID: %s\nFile Metadata: %s\nMatched Keyword: %s\n", service.ServiceName, service.ServiceDisplayName, service.ServiceDescription, service.ServiceCaption, service.ServicePathName, service.ServiceState, service.ServiceProcessId, FileMetaDataParser(service.ServiceExeMetaData), service.ScanMatch)
		fmt.Println(output)
	}
	if err.Error() != "" {
		fmt.Println("error", err)
	}
}

func TestCheckProcesses(t *testing.T) {
	summary, err := CheckProcesses()
	for _, process := range summary {
		output := fmt.Sprintf("\nSuspicious Process Name: %s\nDescription: %s\nCaption: %s\nBinary: %s\nProcessID: %s\nParent Process: %s\nProcess CmdLine : %s\nFile Metadata: %s\nMatched Keyword: %s\n", process.ProcessName, process.ProcessDescription, process.ProcessCaption, process.ProcessPath, process.ProcessPID, process.ProcessParentPID, process.ProcessCmdLine, FileMetaDataParser(process.ProcessExeMetaData), process.ScanMatch)
		fmt.Println(output)
	}
	if err.Error() != "" {
		fmt.Println("error", err)
	}
}

func TestGetFileMetaData(t *testing.T) {
	fileMetaData, err := GetFileMetaData(`C:\Users\hardi\AnyDesk.exe`)
	if err != nil {
		t.Error(err)
	}
	file, _ := json.Marshal(fileMetaData)
	fmt.Println(string(file))
}

func TestGetDirectory(t *testing.T) {
	_, err := CheckDirectory()
	if err != nil {
		t.Error(err)
	}
}

func TestCheckIfAdmin(t *testing.T) {
	status := CheckIfAdmin()
	if status {
		fmt.Println("Running as admin")
	} else {
		t.Error(status)
	}
}

func TestDeObfNames(t *testing.T) {
	for _, name := range EdrList {
		fmt.Println(name)
	}
	for _, name := range RegistryReconList {
		fmt.Println(name)
	}
}

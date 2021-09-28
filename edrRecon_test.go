package edrRecon

import (
	"fmt"
	"testing"
)

var recon EdrHunt

func TestCheckDrivers(t *testing.T) {

	summary, err := recon.CheckDrivers()
	fmt.Println(summary)
	if err.Error() != "" {
		t.Error(err)
	}
}

func TestCheckServices(t *testing.T) {
	summary, err := recon.CheckServices()
	fmt.Println(summary)
	if err.Error() != "" {
		fmt.Println("error", err)
	}
}

func TestCheckProcesses(t *testing.T) {
	summary, err := recon.CheckProcesses()
	fmt.Println(summary)
	if err.Error() != "" {
		fmt.Println("error", err)
	}
}

func TestCheckRegistry(t *testing.T) {
	summary, err := recon.CheckRegistry()
	fmt.Println(summary)
	if err != nil {
		fmt.Println("error", err)
	}
}
func TestGetFileMetaData(t *testing.T) {
	string, err := GetFileMetaData(`C:\Users\hardi\Desktop\ErrorCode.exe`)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string)
}

func TestGetDirectory(t *testing.T) {
	_, err := recon.CheckDirectory()
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

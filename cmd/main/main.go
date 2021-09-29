package main

import (
	"fmt"
	"os"

	"github.com/FourCoreLabs/edrRecon"

	"github.com/spf13/cobra"
)

var (
	drivers      bool
	processes    bool
	services     bool
	registry     bool
	all          bool
	version      string
	versionCheck bool
	recon        edrRecon.EdrHunt
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&drivers, "drivers", "d", drivers, "Scan installed drivers")
	rootCmd.PersistentFlags().BoolVarP(&processes, "processes", "p", processes, "Scan installed processes")
	rootCmd.PersistentFlags().BoolVarP(&services, "services", "s", services, "Scan installed services")
	rootCmd.PersistentFlags().BoolVarP(&registry, "registry", "r", registry, "Scan installed registry")
	rootCmd.PersistentFlags().BoolVarP(&all, "all", "a", all, "runs all scans: drivers, processes, services, registry.")
	rootCmd.PersistentFlags().BoolVarP(&versionCheck, "version", "v", versionCheck, "Output version information and exit")
}

var rootCmd = &cobra.Command{
	Use:   "edrRecon",
	Short: "scans EDR/AV",
	Long:  `edrRecon scans and finds the installed EDR/AV by scanning services, processes, registry, and drivers.`,
	Run: func(cmd *cobra.Command, args []string) {
		if edrRecon.CheckIfAdmin() {
			fmt.Println("Running in adminsitrator mode.")
		} else {
			fmt.Println("Running in user mode, escalate to admin for more details.")
		}
		if versionCheck {
			if version != "" {
				fmt.Printf("edrRecon version: %s\n", version)
				return
			}
			fmt.Printf("edrRecon version: beta-release-v.1\n")
			return
		}
		if processes {
			printProcess()
		}
		if drivers {
			printDrivers()
		}
		if services {
			printServices()
		}
		if registry {
			printServices()
		}
		if all {
			fmt.Println("Scanning processes, services, drivers, and registry...")
			fmt.Println("[PROCESSES]")
			printProcess()
			fmt.Println("[SERVICES]")
			printServices()
			fmt.Println("[DRIVERS]")
			printDrivers()
			fmt.Println("[REGISTRY]")
			printRegistry()
		}
	},
}

func printProcess() {
	summary, _ := recon.CheckProcesses()
	for _, process := range summary {
		output := fmt.Sprintf("\nSuspicious Process Name: %s\nDescription: %s\nCaption: %s\nBinary: %s\nProcessID: %s\nParent Process: %s\nProcess CmdLine : %s\nFile Metadata: %s\nMatched Keyword: %s\n", process.ProcessName, process.ProcessDescription, process.ProcessCaption, process.ProcessPath, process.ProcessPID, process.ProcessParentPID, process.ProcessCmdLine, edrRecon.FileMetaDataParser(process.ProcessExeMetaData), process.ProcessScanMatch)
		fmt.Println(output)
	}
}

func printServices() {
	summary, _ := recon.CheckServices()
	for _, service := range summary {
		output := fmt.Sprintf("\nSuspicious Service Name: %s\nDisplay Name: %s\nDescription: %s\nCaption: %s\nCommandLine: %s\nStatus: %s\nProcessID: %s\nFile Metadata: %s\nMatched Keyword: %s\n", service.ServiceName, service.ServiceDisplayName, service.ServiceDescription, service.ServiceCaption, service.ServicePathName, service.ServiceState, service.ServiceProcessId, edrRecon.FileMetaDataParser(service.ServiceExeMetaData), service.ServiceScanMatch)
		fmt.Println(output)
	}
}

func printRegistry() {
	summary, _ := recon.CheckRegistry()
	fmt.Println("Scanning registry: ")
	for _, match := range summary.RegistryScanMatch {
		fmt.Printf("\t%s\n", match)
	}
}

func printDrivers() {
	summary, _ := recon.CheckDrivers()
	for _, driver := range summary {
		output := fmt.Sprintf("\nSuspicious Driver Module: %s\nDriver FilePath: %s\nDriver File Metadata: %s\nMatched Keyword: %s\n", driver.DriverBaseName, driver.DriverFilePath, edrRecon.FileMetaDataParser(driver.DriverSysMetaData), driver.DriverScanMatch)
		fmt.Println(output)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}

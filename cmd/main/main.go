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
	versionStr   string = "0.3"
	versionCheck bool
	recon        edrRecon.EdrHunt
	scanners     = []edrRecon.EDRDetection{
		&edrRecon.WinDefenderDetection{},
		&edrRecon.KaskperskyDetection{},
	}
)

func edrCommand(cmd *cobra.Command, args []string) {
	if edrRecon.CheckIfAdmin() {
		fmt.Println("Running in adminsitrator mode.")
	} else {
		fmt.Println("Running in user mode, escalate to admin for more details.")
	}

	if all {
		processes = true
		drivers = true
		services = true
		registry = true
		fmt.Println("Scanning processes, services, drivers, and registry...")
	}

	if processes {
		fmt.Println("[PROCESSES]")
		summary, _ := recon.CheckProcesses()
		printProcess(summary)

	}
	if drivers {
		fmt.Println("[DRIVERS]")
		summary, _ := recon.CheckDrivers()
		printDrivers(summary)
	}
	if services {
		fmt.Println("[SERVICES]")
		summary, _ := recon.CheckServices()
		printServices(summary)
	}
	if registry {
		fmt.Println("[REGISTRY]")
		summary, _ := recon.CheckRegistry()
		printRegistry(summary)
	}
}

func versionCommand(cmd *cobra.Command, args []string) {
	if versionStr != "" {
		fmt.Printf("edrRecon version: %s\n", versionStr)
		return
	}
	fmt.Printf("edrRecon version: beta-release-v.1\n")
}

func scanEDRCommand(cmd *cobra.Command, args []string) {
	fmt.Println("[EDR]")
	systemData, _ := recon.GetSystemData()

	for _, scanner := range scanners {
		_, ok := scanner.Detect(systemData)
		if ok {
			fmt.Printf("Detected EDR: %s\n", scanner.Name())
		}
	}
}

func allCommand(cmd *cobra.Command, args []string) {
	all = true
	edrCommand(cmd, args)
	scanEDRCommand(cmd, args)
}

var rootCmd = &cobra.Command{
	Use:   "edrRecon",
	Short: "scans EDR/AV",
	Long:  `edrRecon scans and finds the installed EDR/AV by scanning services, processes, registry, and drivers.`,
	Run:   edrCommand,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "version",
	Long:  `edrRecon version`,
	Run:   versionCommand,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "scan installed edrs",
	Long:  `scan edrs`,
	Run:   scanEDRCommand,
}

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "scan installed edrs",
	Long:  `scan edrs and show system data`,
	Run:   allCommand,
}

func printProcess(summary []edrRecon.ProcessMetaData) {
	for _, process := range summary {
		output := fmt.Sprintf("\nSuspicious Process Name: %s\nDescription: %s\nCaption: %s\nBinary: %s\nProcessID: %s\nParent Process: %s\nProcess CmdLine : %s\nFile Metadata: %s\nMatched Keyword: %s\n", process.ProcessName, process.ProcessDescription, process.ProcessCaption, process.ProcessPath, process.ProcessPID, process.ProcessParentPID, process.ProcessCmdLine, edrRecon.FileMetaDataParser(process.ProcessExeMetaData), process.ScanMatch)

		fmt.Println(output)
	}
}

func printServices(summary []edrRecon.ServiceMetaData) {
	for _, service := range summary {
		output := fmt.Sprintf("\nSuspicious Service Name: %s\nDisplay Name: %s\nDescription: %s\nCaption: %s\nCommandLine: %s\nStatus: %s\nProcessID: %s\nFile Metadata: %s\nMatched Keyword: %s\n", service.ServiceName, service.ServiceDisplayName, service.ServiceDescription, service.ServiceCaption, service.ServicePathName, service.ServiceState, service.ServiceProcessId, edrRecon.FileMetaDataParser(service.ServiceExeMetaData), service.ScanMatch)
		fmt.Println(output)
	}
}

func printRegistry(summary edrRecon.RegistryMetaData) {
	fmt.Println("Scanning registry: ")
	for _, match := range summary.ScanMatch {
		fmt.Printf("\t%s\n", match)
	}
}

func printDrivers(summary []edrRecon.DriverMetaData) {
	for _, driver := range summary {
		output := fmt.Sprintf("\nSuspicious Driver Module: %s\nDriver FilePath: %s\nDriver File Metadata: %s\nMatched Keyword: %s\n", driver.DriverBaseName, driver.DriverFilePath, edrRecon.FileMetaDataParser(driver.DriverSysMetaData), driver.ScanMatch)
		fmt.Println(output)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&drivers, "drivers", "d", drivers, "Scan installed drivers")
	rootCmd.PersistentFlags().BoolVarP(&processes, "processes", "p", processes, "Scan installed processes")
	rootCmd.PersistentFlags().BoolVarP(&services, "services", "s", services, "Scan installed services")
	rootCmd.PersistentFlags().BoolVarP(&registry, "registry", "r", registry, "Scan installed registry")
	rootCmd.PersistentFlags().BoolVarP(&versionCheck, "version", "v", versionCheck, "Output version information and exit")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(allCmd)
}

func main() {
	Execute()
}

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/FourCoreLabs/EDRHunt/pkg/edrRecon"
	"github.com/FourCoreLabs/EDRHunt/pkg/resources"
	"github.com/FourCoreLabs/EDRHunt/pkg/scanners"
	"github.com/spf13/cobra"
)

var (
	drivers      bool
	processes    bool
	services     bool
	registry     bool
	all          bool
	versionStr   string = "1.3.1"
	versionCheck bool
)

func printBanner() {
	fmt.Printf(`
    __________  ____     __  ____  ___   ________
   / ____/ __ \/ __ \   / / / / / / / | / /_  __/
  / __/ / / / / /_/ /  / /_/ / / / /  |/ / / /   
 / /___/ /_/ / _, _/  / __  / /_/ / /|  / / /    
/_____/_____/_/ |_|  /_/ /_/\____/_/ |_/ /_/     																				

FourCore Labs (https://fourcore.io) | Version: %v

`, versionStr)
}

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
		summary, _ := edrRecon.CheckProcesses()
		printProcess(summary)
		fmt.Println()
	}
	if drivers {
		fmt.Println("[DRIVERS]")
		summary, _ := edrRecon.CheckDrivers()
		printDrivers(summary)
		fmt.Println()
	}
	if services {
		fmt.Println("[SERVICES]")
		summary, _ := edrRecon.CheckServices()
		printServices(summary)
		fmt.Println()
	}
	if registry {
		fmt.Println("[REGISTRY]")
		summary, _ := edrRecon.CheckRegistry(context.Background())
		printRegistry(summary)
		fmt.Println()
	}
}

func versionCommand(cmd *cobra.Command, args []string) {
	fmt.Printf("version: %s\n", versionStr)
}

func scanEDRCommand(cmd *cobra.Command, args []string) {
	fmt.Println("[EDR]")
	systemData, _ := edrRecon.GetSystemData(context.Background())

	for _, scanner := range scanners.Scanners {
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
	Use:   "EDRHunt",
	Short: "scans EDR/AV",
	Long:  `EDRHunt scans and finds the installed EDR/AV by scanning services, processes, registry, and drivers.`,
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

func printProcess(summary []resources.ProcessMetaData) {
	for _, process := range summary {
		fmt.Printf("Suspicious Process Name: %s\n", process.ProcessName)
		fmt.Printf("Description: %s\n", process.ProcessDescription)
		fmt.Printf("Caption: %s\n", process.ProcessCaption)
		fmt.Printf("Binary: %s\n", process.ProcessPath)
		fmt.Printf("ProcessID: %s\n", process.ProcessPID)
		fmt.Printf("Parent Process: %s\n", process.ProcessParentPID)
		fmt.Printf("Process CmdLine: %s\n", process.ProcessCmdLine)
		fmt.Printf("File Metadata: \t%s\n", edrRecon.FileMetaDataParser(process.ProcessExeMetaData))
		fmt.Printf("Matched Keyword: %s\n", process.ScanMatch)
		fmt.Println()
	}
}

func printServices(summary []resources.ServiceMetaData) {
	for _, service := range summary {
		fmt.Printf("Suspicious Service Name: %s\n", service.ServiceName)
		fmt.Printf("Display Name: %s\n", service.ServiceDisplayName)
		fmt.Printf("Caption: %s\n", service.ServiceCaption)
		fmt.Printf("CommandLine: %s\n", service.ServicePathName)
		fmt.Printf("Status: %s\n", service.ServiceState)
		fmt.Printf("ProcessID: %s\n", service.ServiceProcessId)
		fmt.Printf("File Metadata: \t%s\n", edrRecon.FileMetaDataParser(service.ServiceExeMetaData))
		fmt.Printf("Matched Keyword: %s\n", service.ScanMatch)
		fmt.Println()
	}
}

func printRegistry(summary resources.RegistryMetaData) {
	fmt.Println("Scanning registry: ")
	for _, match := range summary.ScanMatch {
		fmt.Printf("\t%s\n", match)
	}
	fmt.Println()
}

func printDrivers(summary []resources.DriverMetaData) {
	for _, driver := range summary {
		fmt.Printf("Suspicious Driver Module: %s\n", driver.DriverBaseName)
		fmt.Printf("Driver FilePath: %s\n", driver.DriverFilePath)
		fmt.Printf("Driver File Metadata: \t%s\n", edrRecon.FileMetaDataParser(driver.DriverSysMetaData))
		fmt.Printf("Matched Keyword: %s\n", driver.ScanMatch)
		fmt.Println()
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
	fmt.Print("\033[H\033[2J")
	printBanner()
	Execute()
}

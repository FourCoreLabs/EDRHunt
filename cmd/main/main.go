package main

import (
	"fmt"
	"os"
	"strings"

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

		if versionCheck {
			if version != "" {
				fmt.Printf("edrRecon version: %s\n", version)
				return
			}
			fmt.Printf("edrRecon version: beta-release-v.1\n")
			return
		}

		// if len(args) == 0 {
		// 	fmt.Printf("edrRecon requires at least one parameter, --help for usage.")
		// 	os.Exit(1)
		// }

		var recon edrRecon.EdrHunt

		if processes {
			summary, _ := recon.CheckProcesses()
			if summary == "" {
				fmt.Println("no suspicious processes found")
			}
			fmt.Println(summary)
		}
		if drivers {
			summary, _ := recon.CheckDrivers()
			if summary == "" {
				fmt.Println("no suspicious drivers found")
			}
			fmt.Println(summary)
		}
		if services {
			summary, _ := recon.CheckServices()
			if summary == "" {
				fmt.Println("no suspicious services found")
			}
			fmt.Println(summary)
		}
		if registry {
			summary, _ := recon.CheckRegistry()
			if summary == "" {
				fmt.Println("no suspicious registry found")
			}
			fmt.Println(summary)
		}
		if all {
			var allData []string
			registry, _ := recon.CheckRegistry()
			if registry != "" {
				allData = append(allData, registry)
			}
			service, _ := recon.CheckServices()
			if service != "" {
				allData = append(allData, "\n", service)
			}
			drivers, _ := recon.CheckDrivers()
			if drivers != "" {
				allData = append(allData, "\n", drivers)
			}
			process, _ := recon.CheckProcesses()
			if process != "" {
				allData = append(allData, "\n", process)
			}
			fmt.Printf("%s\n", strings.Join(allData, ""))
		}
	},
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

package main

import (
	"fmt"
	"os"

	"github.com/FourCoreLabs/edrRecon"

	"github.com/spf13/cobra"
)

var (
	drivers   bool
	processes bool
	services  bool
	registry  bool
	all       bool
	version   bool
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&drivers, "drivers", "d", drivers, "Scan installed drivers")
	rootCmd.PersistentFlags().BoolVarP(&processes, "processes", "p", processes, "Scan installed processes")
	rootCmd.PersistentFlags().BoolVarP(&services, "services", "s", services, "Scan installed services")
	rootCmd.PersistentFlags().BoolVarP(&registry, "registry", "r", registry, "Scan installed registry")
	rootCmd.PersistentFlags().BoolVarP(&all, "all", "a", all, "runs all scans: drivers, processes, services, registry.")
	rootCmd.PersistentFlags().BoolVarP(&version, "version", "v", version, "Output version information and exit")
}

var rootCmd = &cobra.Command{
	Use:   "edrRecon",
	Short: "scans EDR/AV",
	Long:  `edrRecon scans and finds the installed EDR/AV by scanning services, processes, registry, and drivers.`,
	Run: func(cmd *cobra.Command, args []string) {

		if version {
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

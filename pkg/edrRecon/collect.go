package edrRecon

import (
	"context"
	"fmt"

	"github.com/FourCoreLabs/EDRHunt/pkg/resources"
)

// GetSystemData collects the parsed list of processes, services, drivers, wmi and registry keys to be used for EDR heuristics.
func GetSystemData(ctx context.Context) (resources.SystemData, error) {
	var err error
	var systemData resources.SystemData

	systemData.Processes, err = CheckProcesses()
	if err != nil {
		return systemData, fmt.Errorf("failed to check processes: %w", err)
	}

	systemData.Services, err = CheckServices()
	if err != nil {
		return systemData, fmt.Errorf("failed to check services: %w", err)
	}

	systemData.Registry, err = CheckRegistry(ctx)
	if err != nil {
		return systemData, fmt.Errorf("failed to check registry: %w", err)
	}

	systemData.Drivers, err = CheckDrivers()
	if err != nil {
		return systemData, fmt.Errorf("failed to check drivers: %w", err)
	}

	systemData.AVProviders, err = CheckAVWmiRepo()
	if err != nil {
		return systemData, fmt.Errorf("failed to check wmi repo: %w", err)
	}
	return systemData, nil
}

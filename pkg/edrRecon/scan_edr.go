package edrRecon

func (e *EdrHunt) GetSystemData() (SystemData, error) {
	var systemData SystemData

	systemData.Processes, err = e.CheckProcesses()
	if err != nil {
		return systemData, err
	}

	systemData.Services, err = e.CheckServices()
	if err != nil {
		return systemData, err
	}

	systemData.Registry, err = e.CheckRegistry()
	if err != nil {
		return systemData, err
	}

	systemData.Drivers, err = e.CheckDrivers()
	if err != nil {
		return systemData, err
	}

	return systemData, nil
}

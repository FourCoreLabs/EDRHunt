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

type SystemData struct {
	Processes []ProcessMetaData
	Registry  RegistryMetaData
	Services  []ServiceMetaData
	Drivers   []DriverMetaData
}

func (s *SystemData) CountMatchesAll(keywords ...[]string) (int, bool) {
	var match bool
	var count int

	scanMatchList := make([]string, 0)

	for _, v := range s.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range s.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range s.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, s.Registry.ScanMatch...)

	var totalLen int
	for _, v := range keywords {
		totalLen += len(v)
	}
	keywordList := make([]string, 0, totalLen)

	for _, v := range keywords {
		keywordList = append(keywordList, v...)
	}

	for _, v := range keywordList {
		contains := StrSliceContains(scanMatchList, v)
		if contains {
			match = true
			count++
		}
	}

	return count, match
}

type EDRDetection interface {
	Detect(data SystemData) (EDRType, bool)
	Name() string
	Type() EDRType
}

type EDRType string

var (
	WinDefenderEDR EDRType = "defender"
	KaskperskyEDR  EDRType = "kaspersky"
	CrowdstrikeEDR EDRType = "crowdstrike"
	McafeeEDR      EDRType = "mcafee"
	SymantecEDR    EDRType = "symantec"
	CylanceEDR     EDRType = "cylance"
	CarbonBlackEDR EDRType = "carbon_black"
	SentinelOneEDR EDRType = "sentinel_one"
	FireEyeEDR     EDRType = "fireeye"
)

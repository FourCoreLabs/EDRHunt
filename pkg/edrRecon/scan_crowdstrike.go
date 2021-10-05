package edrRecon

type CrowdstrikeDetection struct{}

func (w *CrowdstrikeDetection) Name() string {
	return "Crowdstrike EDR Solution"
}

func (w *CrowdstrikeDetection) Type() EDRType {
	return SymantecEDR
}

var CrowdstrikeHeuristic = []string{
	"CrowdStrike",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsDeviceControl.inf",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsFirmwareAnalysis.inf",
}

func (w *CrowdstrikeDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(CrowdstrikeHeuristic)
	if !ok {
		return "", false
	}

	return CrowdstrikeEDR, true
}

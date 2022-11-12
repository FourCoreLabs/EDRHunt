package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type SophosDetection struct{}

func (w *SophosDetection) Name() string {
	return "Sophos"
}

func (w *SophosDetection) Type() resources.EDRType {
	return resources.SophosEDR
}

var SophosHeuristic = []string{
	"Sophos",
	"Sophos Virus Removal Tool install.exe",
	"SCTCleanupService.exe",
	"SVRTservice.exe",
	"Sophos Computer Security Scan.exe",
	"SophosLinkIconHandler32.dll",
}

func (w *SophosDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(SophosHeuristic)
	if !ok {
		return "", false
	}

	return resources.SophosEDR, true
}

package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type WinDefenderDetection struct{}

func (w *WinDefenderDetection) Name() string {
	return "Windows Defender"
}

func (w *WinDefenderDetection) Type() resources.EDRType {
	return resources.WinDefenderEDR
}

var WinDefenderProcessHeuristic = []string{
	"defender",
	"msmpeng",
}

var WinDefenderServicesHeuristic = []string{
	"defender",
	"msmpeng",
}

var WinDefenderDriverHeuristic = []string{
	"defender",
}

var WinDefenderRegistryHeuristic = []string{
	"Windows Defender",
}

// Detect returnns EDRType `defender`
// If
// 			- processes list contains WinDefenderProcessHeuristic keywords
// 			- services list contains WinDefenderServicesHeuristic keywords
// 			- registry list contains WinDefenderRegistryHeuristic keywords
// 			- driver list contains WinDefenderDriverHeuristic keywords
func (w *WinDefenderDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(WinDefenderDriverHeuristic, WinDefenderProcessHeuristic, WinDefenderRegistryHeuristic, WinDefenderServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.WinDefenderEDR, true
}

package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type SymantecDetection struct{}

func (w *SymantecDetection) Name() string {
	return "Symantec Endpoint Security"
}

func (w *SymantecDetection) Type() resources.EDRType {
	return resources.SymantecEDR
}

var SymantecHeuristic = []string{
	"symantec",
	"symcorpu",
	"symefasi",
	"Symantec",
	"Symantec Endpoint Protection\\",
}

func (w *SymantecDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(SymantecHeuristic)
	if !ok {
		return "", false
	}

	return resources.SymantecEDR, true
}

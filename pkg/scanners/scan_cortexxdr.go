package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type CortexXDRDetection struct{}

func (w *CortexXDRDetection) Name() string {
	return "Cortex XDR"
}

func (w *CortexXDRDetection) Type() resources.EDRType {
	return resources.CortexXDREDR
}

var CortexXDRHeuristic = []string{
	"cyserver.exe",
	"Cortex XDR",
}

func (w *CortexXDRDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CortexXDRHeuristic)
	if !ok {
		return "", false
	}

	return resources.CortexXDREDR, true
}

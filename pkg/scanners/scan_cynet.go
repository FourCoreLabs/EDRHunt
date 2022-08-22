package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type CynetDetection struct{}

func (w *CynetDetection) Name() string {
	return "Cynet"
}

func (w *CynetDetection) Type() resources.EDRType {
	return resources.CynetEDR
}

var CynetHeuristic = []string{
	"Cynet",
	"Cyops",
	"Cynet EPS",
}

func (w *CynetDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CynetHeuristic)
	if !ok {
		return "", false
	}

	return resources.CynetEDR, true
}

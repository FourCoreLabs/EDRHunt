package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type CheckPointDetection struct{}

func (w *CheckPointDetection) Name() string {
	return "Carbon Black"
}

func (w *CheckPointDetection) Type() resources.EDRType {
	return resources.CheckPointEDR
}

var CheckPointHeuristic = []string{
	"Checkpoint",
}

func (w *CheckPointDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CheckPointHeuristic)
	if !ok {
		return "", false
	}

	return resources.CheckPointEDR, true
}

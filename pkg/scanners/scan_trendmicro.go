package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type TrendMicroDetection struct{}

func (w *TrendMicroDetection) Name() string {
	return "Trend Micro Deep Security"
}

func (w *TrendMicroDetection) Type() resources.EDRType {
	return resources.TrendMicroEDR
}

var TrendMicroHeuristic = []string{
	"Deep Security Agent\\",
	"dsa",
	"Notifier",
	"Trend Micro",
}

func (w *TrendMicroDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(TrendMicroHeuristic)
	if !ok {
		return "", false
	}

	return resources.QualysEDR, true
}

package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type DeepInstictDetection struct{}

func (w *DeepInstictDetection) Name() string {
	return "Deep Instinct Security"
}

func (w *DeepInstictDetection) Type() resources.EDRType {
	return resources.DeepInstinctEDR
}

var DeepInstinctHeuristic = []string{
	"Deep Instinct",
}

func (w *DeepInstictDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(DeepInstinctHeuristic)
	if !ok {
		return "", false
	}

	return resources.DeepInstinctEDR, true
}

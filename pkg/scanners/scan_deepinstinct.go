package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type DeepInstictDetection struct{}

func (w *DeepInstictDetection) Name() string {
	return "Deep Instinct Security"
}

func (w *DeepInstictDetection) Type() resources.EDRType {
	return resources.DeepInstinctEDR
}

var DeepInstinctHeuristic = []string{
	"DeepInstinct",
	"Deep Instinct Agent",
	"Deep Instinct Prevention Platform",
	"HKEY_LOCAL_MACHINE\\SOFTWARE\\Deep Instinct",
}

func (w *DeepInstictDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(DeepInstinctHeuristic)
	if !ok {
		return "", false
	}

	return resources.DeepInstinctEDR, true
}

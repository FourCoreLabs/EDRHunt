package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type KaskperskyDetection struct{}

func (w *KaskperskyDetection) Name() string {
	return "Kaspersky Security"
}

func (w *KaskperskyDetection) Type() resources.EDRType {
	return resources.KaskperskyEDR
}

var KasperskyHeuristic = []string{
	"kaspersky",
}

func (w *KaskperskyDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(KasperskyHeuristic)
	if !ok {
		return "", false
	}

	return resources.KaskperskyEDR, true
}

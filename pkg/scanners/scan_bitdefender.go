package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type BitDefenderDetection struct{}

func (w *BitDefenderDetection) Name() string {
	return "BitDefender"
}

func (w *BitDefenderDetection) Type() resources.EDRType {
	return resources.BitDefenderEDR
}

var BitDefenderHeuristic = []string{
	"BitDefender",
}

func (w *BitDefenderDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(BitDefenderHeuristic)
	if !ok {
		return "", false
	}

	return resources.BitDefenderEDR, true
}

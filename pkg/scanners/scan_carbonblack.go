package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type CarbonBlackDetection struct{}

func (w *CarbonBlackDetection) Name() string {
	return "Carbon Black"
}

func (w *CarbonBlackDetection) Type() resources.EDRType {
	return resources.CarbonBlackEDR
}

var CarbonBlackHeuristic = []string{
	"CarbonBlack\\",
	"CbDefense\\",
	"CarbonBlackClientSetup.exe",
}

func (w *CarbonBlackDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CarbonBlackHeuristic)
	if !ok {
		return "", false
	}

	return resources.CarbonBlackEDR, true
}

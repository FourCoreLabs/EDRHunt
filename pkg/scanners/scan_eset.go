package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type ESETEDRDetection struct{}

func (w *ESETEDRDetection) Name() string {
	return "ESET Endpoint Security"
}

func (w *ESETEDRDetection) Type() resources.EDRType {
	return resources.ESETEDR
}

var ESETHeuristic = []string{
	"ESET",
	"ESET Endpoint Security",
	"ecmd",
	"ekrn",
}

func (w *ESETEDRDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(ESETHeuristic)
	if !ok {
		return "", false
	}

	return resources.QualysEDR, true
}

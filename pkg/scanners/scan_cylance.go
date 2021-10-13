package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type CylanceDetection struct{}

func (w *CylanceDetection) Name() string {
	return "Cylance Smart Antivirus"
}

func (w *CylanceDetection) Type() resources.EDRType {
	return resources.CylanceEDR
}

var CylanceHeuristic = []string{
	"Cylance\\",
	"Cylance0",
	"Cylance1",
	"Cylance2",
}

func (w *CylanceDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CylanceHeuristic)
	if !ok {
		return "", false
	}

	return resources.CylanceEDR, true
}

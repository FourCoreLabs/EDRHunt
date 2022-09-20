package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type LimacharlieDetection struct{}

func (w *LimacharlieDetection) Name() string {
	return "Limacharlie EDR"
}

func (w *LimacharlieDetection) Type() resources.EDRType {
	return resources.LimacharlieEDR
}

var LimacharlieHeuristic = []string{
	"lc_sensor.exe",
	"refractionPOINT HCP",
	"LimaCharlie",
}

func (w *LimacharlieDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(LimacharlieHeuristic)
	if !ok {
		return "", false
	}

	return resources.DeepInstinctEDR, true
}

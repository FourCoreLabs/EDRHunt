package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type LimacharlieDetection struct{}

func (w *LimacharlieDetection) Name() string {
	return "Limacharlie Agent"
}

func (w *LimacharlieDetection) Type() resources.EDRType {
	return resources.LimacharlieEDR
}

var LimacharlieHeuristic = []string{
	"rphcp.exe",
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

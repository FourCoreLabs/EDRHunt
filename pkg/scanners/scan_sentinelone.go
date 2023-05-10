package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type SentinelOneDetection struct{}

func (w *SentinelOneDetection) Name() string {
	return "SentinelOne"
}

func (w *SentinelOneDetection) Type() resources.EDRType {
	return resources.SentinelOneEDR
}

var SentinelOneHeuristic = []string{
	"SentinelOne\\",
	"C:\\Program Files\\SentinelOne",
	"SentinelAgent",
	"SentinelMonitor",
}

func (w *SentinelOneDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(SentinelOneHeuristic)
	if !ok {
		return "", false
	}

	return resources.SentinelOneEDR, true
}

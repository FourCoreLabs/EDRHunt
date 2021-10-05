package edrRecon

type SentinelOneDetection struct{}

func (w *SentinelOneDetection) Name() string {
	return "SentinelOne"
}

func (w *SentinelOneDetection) Type() EDRType {
	return SentinelOneEDR
}

var SentinelOneHeuristic = []string{
	"SentinelOne\\",
	"CbDefense\\",
	"SensorVersion",
}

func (w *SentinelOneDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(SentinelOneHeuristic)
	if !ok {
		return "", false
	}

	return SentinelOneEDR, true
}

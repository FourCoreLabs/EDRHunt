package edrRecon

type CarbonBlackDetection struct{}

func (w *CarbonBlackDetection) Name() string {
	return "Carbon Black"
}

func (w *CarbonBlackDetection) Type() EDRType {
	return CarbonBlackEDR
}

var CarbonBlackHeuristic = []string{
	"CarbonBlack\\",
	"CbDefense\\",
	"SensorVersion",
}

func (w *CarbonBlackDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(CarbonBlackHeuristic)
	if !ok {
		return "", false
	}

	return CarbonBlackEDR, true
}

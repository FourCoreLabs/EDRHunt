package edrRecon

type CylanceDetection struct{}

func (w *CylanceDetection) Name() string {
	return "Cylance Smart Antivirus"
}

func (w *CylanceDetection) Type() EDRType {
	return CylanceEDR
}

var CylanceHeuristic = []string{
	"Cylance\\",
	"Cylance0",
	"Cylance1",
	"Cylance2",
}

func (w *CylanceDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(CylanceHeuristic)
	if !ok {
		return "", false
	}

	return CylanceEDR, true
}

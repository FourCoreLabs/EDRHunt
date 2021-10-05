package edrRecon

type SymantecDetection struct{}

func (w *SymantecDetection) Name() string {
	return "Symantec Endpoint Security"
}

func (w *SymantecDetection) Type() EDRType {
	return SymantecEDR
}

var SymantecHeuristic = []string{
	"symantec",
	"symcorpu",
	"symefasi",
	"Symantec",
	"Symantec Endpoint Protection\\",
}

func (w *SymantecDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(SymantecHeuristic)
	if !ok {
		return "", false
	}

	return SymantecEDR, true
}

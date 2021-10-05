package edrRecon

type FireEyeDetection struct{}

func (w *FireEyeDetection) Name() string {
	return "FireEye"
}

func (w *FireEyeDetection) Type() EDRType {
	return FireEyeEDR
}

var FireEyeHeuristic = []string{
	"FireEye",
}

func (w *FireEyeDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(FireEyeHeuristic)
	if !ok {
		return "", false
	}

	return FireEyeEDR, true
}

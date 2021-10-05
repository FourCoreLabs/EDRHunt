package edrRecon

type KaskperskyDetection struct{}

func (w *KaskperskyDetection) Name() string {
	return "Kaspersky Security"
}

func (w *KaskperskyDetection) Type() EDRType {
	return KaskperskyEDR
}

var KasperskyHeuristic = []string{
	"kaspersky",
}

func (w *KaskperskyDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(KasperskyHeuristic)
	if !ok {
		return "", false
	}

	return KaskperskyEDR, true
}

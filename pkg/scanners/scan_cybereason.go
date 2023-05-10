package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type CybereasonDetection struct{}

func (w *CybereasonDetection) Name() string {
	return "Cybereason"
}

func (w *CybereasonDetection) Type() resources.EDRType {
	return resources.CybereasonEDR
}

var CybereasonHeuristic = []string{
	"CybereasonRansomFreeServiceHost.exe",
	"Cybereason",
	"Cybereason ActiveProbe\\",
	"CrAmTray.exe",
	"Cybereason",
	"crsdll.dll",
	"CoreMinion.dll",
	"CoreMinion",
	"minionhost.exe",
	"Cybereason Sensor",
	"CybereasonSensor.exe",
}

func (w *CybereasonDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CybereasonHeuristic)
	if !ok {
		return "", false
	}

	return resources.CybereasonEDR, true
}

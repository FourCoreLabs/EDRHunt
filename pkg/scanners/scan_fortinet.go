package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type FortinetDetection struct{}

func (w *FortinetDetection) Name() string {
	return "Fortinet"
}

func (w *FortinetDetection) Type() resources.EDRType {
	return resources.FortinetEDR
}

var FortinetHeuristic = []string{
	"Fortinet",
	"fortifw.exe",
	"fortitray.exe",
	"fortiwad.exe",
	"fortiproxy.exe",
	"fortiskin.dll",
	"fortiscand.exe",
	"fortivpnst.dll",
	"fortivpnst.exe",
	"fortivpnst64.dll",
	"forticlient.exe",
	"forticlish.dll",
	"FortiClient Service Scheduler",
	"FortiClient.exe",
	"fortiwad.exe",
}

func (w *FortinetDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(FortinetHeuristic)
	if !ok {
		return "", false
	}

	return resources.FortinetEDR, true
}

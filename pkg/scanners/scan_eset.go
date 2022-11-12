package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type ESETEDRDetection struct{}

func (w *ESETEDRDetection) Name() string {
	return "ESET Endpoint Security"
}

func (w *ESETEDRDetection) Type() resources.EDRType {
	return resources.ESETEDR
}

var ESETHeuristic = []string{
	"ESET NOD32 Antivirus",
	"egui.exe",
	"ekrn.exe",
	"emu-rep.exe",
	"emu_install.exe",
	"emu-cci.exe",
	"emu-gui.exe",
	"emu-uninstall.exe",
	"emu-gui.exe",
	"ESET MSP Utilities",
	"C:\\Program Files\\ESET\\ESET NOD32 Antivirus\\ecmd.exe",
}

func (w *ESETEDRDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(ESETHeuristic)
	if !ok {
		return "", false
	}

	return resources.QualysEDR, true
}

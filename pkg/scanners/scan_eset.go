package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type ESETEDRDetection struct{}

func (w *ESETEDRDetection) Name() string {
	return "ESET Endpoint Security"
}

func (w *ESETEDRDetection) Type() resources.EDRType {
	return resources.ESETEDR
}

var ESETHeuristic = []string{
	"egui.exe",
	"ekrn.exe",
	"minodlogin.exe",
	"minodlogin",
	"emu-rep.exe",
	"emu_install.exe",
	"emu-cci.exe",
	"emu-gui.exe",
	"emu-uninstall.exe",
	"emu-gui.exe",
	"ESET MSP Utilities",
	"C:\\Program Files\\ESET\\ESET NOD32 Antivirus\\ecmd.exe",
	"eguiAmon.dll",
	"eguiDevmon.dll",
	"eguiDmon.dll",
	"eguiEmon.dll",
	"eguiEpfw.dll",
	"eguiHips.dll",
	"eguiMailPlugins.dll",
	"eguiParental.dll",
	"eguiProduct.dll",
	"eguiProductRcd.dll",
	"eguiScan.dll",
	"eguiSmon.dll",
	"eguiUpdate.dll",
	"EHttpSrv.exe",
	"eplgHooks.dll",
	"eplgOE.dll",
	"eclsLang.dll",
	"eguiAmonLang.dll",
	"eguiEpfwLang.dll",
	"eguiHipsLang.dll",
	"eguiLang.dll",
	"eguiOnlineHelp.dll",
	"eguiOnlineHelpLang.dll",
	"eguiScanLang.dll",
	"eguiSmonLang.dll",
	"eguiUpdateLang.dll",
	"eguiWebControl.dll",
	"ekrnDevmonLang.dll",
	"ekrnEpfwLang.dll",
	"ekrnHipsLang.dll",
}

func (w *ESETEDRDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(ESETHeuristic)
	if !ok {
		return "", false
	}

	return resources.QualysEDR, true
}

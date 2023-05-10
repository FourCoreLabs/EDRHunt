package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type CylanceDetection struct{}

func (w *CylanceDetection) Name() string {
	return "Cylance Smart Antivirus"
}

func (w *CylanceDetection) Type() resources.EDRType {
	return resources.CylanceEDR
}

var CylanceHeuristic = []string{
	"Cylance",
	"CylanceProtectSetup.exe",
	"cylancesvc.exe",
	"CylanceUI.exe",
	"CylanceProtect",
	"CylanceProtectSetup.exe",
	"cylance.updatemgr.interfaces.dll",
	"cylancesvc.exe",
	"cylance.host.updater.dll",
	"cylance.host.versions.dll",
	"cylance.host.analysis.dll",
	"cylance.host.ccui.interfaces.dll",
	"cylance.host.commandcontrolui.dll",
	"cylance.host.controller.dll",
	"cylance.host.cylancevenue.dll",
	"cylance.host.infinitymodel.dll",
	"cylance.host.windowseventlogwriter.dll",
	"cylance.interfaces.dll",
	"cymemdef.dll",
	"cyprotectdrv64.sys",
	"cyupdate.exe",
	"cyhelper64.dl",
	"cylanceui.exe",
	"cymemdef64.dll",
	"cylance.host.cylancevenuemodule.dll",
	"cylance.host.memdefps_gac.dll",
	"cylance.host.systeminformation.dll",
	"cymemdefps.dll",
	"cymemdefps64.dll",
	"cylance.host.wmiprovider_gac.dll",
	"cylance.host.infinitymodelole.dll",
	"cylance.host.infinitymodelpdf.dll",
}

func (w *CylanceDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CylanceHeuristic)
	if !ok {
		return "", false
	}

	return resources.CylanceEDR, true
}

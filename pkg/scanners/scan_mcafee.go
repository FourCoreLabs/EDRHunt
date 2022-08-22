package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type McafeeDetection struct{}

func (w *McafeeDetection) Name() string {
	return "McAfee MVISION Endpoint Detection and Response"
}

func (w *McafeeDetection) Type() resources.EDRType {
	return resources.McafeeEDR
}

var McafeeHeuristic = []string{
	"Mcafee\\",
	"mcupdate.exe",
	"ProtectedModuleHost.exe",
	"McAfeeAgent\\",
	"APPolicyName",
	"EPPolicyName",
	"OASPolicyName",
	"ESConfigTool.exe",
	"FWInstCheck.exe",
	"FwWindowsFirewallHandler.exe",
	"mfeesp.exe",
	"mfefw.exe",
	"mfeProvisionModeUtility.exe",
	"mfetp.exe",
	"WscAVExe.exe",
	"mcshield.exe",
	"McChHost.exe",
	"mfewc.exe",
	"mfewch.exe",
	"mfewcui.exe",
	"fwinfo.exe",
	"mfecanary.exe",
	"mfefire.exe",
	"mfehidin.exe",
	"mfemms.exe",
	"mfevtps.exe",
	"mmsinfo.exe",
	"vtpinfo.exe",
	"MarSetup.exe",
	"mctray.exe",
	"masvc.exe",
	"macmnsvc.exe",
	"MfeServiceMgr.exe ",
	"McAPExe.exe",
	"McPvTray.exe",
	"mcods.exe",
	"mcuicnt.exe",
	"mcuihost.exe",
	"Mcshield.exe",
	"xtray.exe",
	"McpService.exe",
	"epefprtrainer.exe",
	"mfeffcoreservice.exe",
	"MfeEpeSvc.exe",
}

func (w *McafeeDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(McafeeHeuristic)
	if !ok {
		return "", false
	}

	return resources.McafeeEDR, true
}

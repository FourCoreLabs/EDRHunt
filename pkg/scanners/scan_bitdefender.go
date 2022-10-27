package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type BitDefenderDetection struct{}

func (w *BitDefenderDetection) Name() string {
	return "BitDefender"
}

func (w *BitDefenderDetection) Type() resources.EDRType {
	return resources.BitDefenderEDR
}

var BitDefenderHeuristic = []string{
	"BitDefender",
	"bdagent.exe",
	"AntiphishingAgent.dll",
	"bdcloud.dll",
	"bdmltusrsrv.dll",
	"bdnc.dll",
	"bdfndisf6.sys",
	"bdfwcore.dll",
	"bdfwfpf.sys",
	"bdpredir.dll",
	"bdquar.dll",
	"avc3.sys",
	"avckf.sys",
	"alertvs10u.http.dll",
	"amvs10u.http.dll",
	"aphvs10u.http.dll",
	"bdch.dll",
	"bdchsubmit.dll",
	"BdFirewallSDK.dll",
	"bdreinit.exe",
	"bdpredir_ssl.dl",
	"pdscan.exe",
	"pdiface.exe",
	"pdiface.exe",
	"bdnc.dll",
	"BDSubmit.dll",
	"BDSubWiz.exe",
	"bdch.dll",
	"bdec.dll",
	"bdreinit.exe",
}

func (w *BitDefenderDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(BitDefenderHeuristic)
	if !ok {
		return "", false
	}

	return resources.BitDefenderEDR, true
}

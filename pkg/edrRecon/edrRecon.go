package edrRecon

type Recon interface {
	CheckProcesses() ([]ProcessMetaData, error)
	CheckServices() ([]ServiceMetaData, error)
	CheckDrivers() ([]DriverMetaData, error)
	CheckRegistry() (RegistryMetaData, error)
	CheckDirectory() (string, error)
}

type EdrHunt struct{}

type FileMetaData struct {
	ProductName      string
	OriginalFilename string
	InternalFileName string
	CompanyName      string
	FileDescription  string
	ProductVersion   string
	Comments         string
	LegalCopyright   string
	LegalTrademarks  string
}

type ServiceMetaData struct {
	ServiceName        string
	ServiceDisplayName string
	ServiceDescription string
	ServiceCaption     string
	ServicePathName    string
	ServiceState       string
	ServiceProcessId   string
	ServiceExeMetaData FileMetaData
	ScanMatch          []string
}

type ProcessMetaData struct {
	ProcessName        string
	ProcessPath        string
	ProcessDescription string
	ProcessCaption     string
	ProcessCmdLine     string
	ProcessPID         string
	ProcessParentPID   string
	ProcessExeMetaData FileMetaData
	ScanMatch          []string
}

type DriverMetaData struct {
	DriverBaseName    string
	DriverFilePath    string
	DriverSysMetaData FileMetaData
	ScanMatch         []string
}

type RegistryMetaData struct {
	ScanMatch []string
}

type SystemData struct {
	Processes []ProcessMetaData
	Registry  RegistryMetaData
	Services  []ServiceMetaData
	Drivers   []DriverMetaData
}

type EDRDetection interface {
	Detect(data SystemData) (EDRType, bool)
	Name() string
	Type() EDRType
}

//  -----------------------------------------------------------------------
type WinDefenderDetection struct{}

func (w *WinDefenderDetection) Name() string {
	return "Windows Defender"
}

func (w *WinDefenderDetection) Type() EDRType {
	return WinDefenderEDR
}

var WinDefenderProcessHeuristic = []string{
	"defender",
	"msmpeng",
}

var WinDefenderServicesHeuristic = []string{
	"defender",
	"msmpeng",
}

var WinDefenderDriverHeuristic = []string{
	"defender",
}

var WinDefenderRegistryHeuristic = []string{
	"Windows Defender",
}

// Detect returnns EDRType `defender`
// If
// 			- processes list contains WinDefenderProcessHeuristic keywords
// 			- services list contains WinDefenderServicesHeuristic keywords
// 			- registry list contains WinDefenderRegistryHeuristic keywords
// 			- driver list contains WinDefenderDriverHeuristic keywords
func (w *WinDefenderDetection) Detect(data SystemData) (EDRType, bool) {
	var (
		match bool
	)

	scanMatchList := make([]string, 0)

	for _, v := range data.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, data.Registry.ScanMatch...)

	keywordList := make([]string, 0, len(WinDefenderDriverHeuristic)+len(WinDefenderProcessHeuristic)+len(WinDefenderRegistryHeuristic)+len(WinDefenderServicesHeuristic))
	keywordList = append(keywordList, WinDefenderProcessHeuristic...)
	keywordList = append(keywordList, WinDefenderDriverHeuristic...)
	keywordList = append(keywordList, WinDefenderRegistryHeuristic...)
	keywordList = append(keywordList, WinDefenderServicesHeuristic...)

	for _, v := range keywordList {
		contains := StrSliceContains(scanMatchList, v)
		if contains {
			match = true
		}
	}

	if !match {
		return "", false
	}

	return WinDefenderEDR, true
}

//  -----------------------------------------------------------------------
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
	var (
		match bool
	)

	scanMatchList := make([]string, 0)

	for _, v := range data.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, data.Registry.ScanMatch...)

	keywordList := make([]string, 0, len(KasperskyHeuristic))
	keywordList = append(keywordList, KasperskyHeuristic...)

	for _, v := range keywordList {
		contains := StrSliceContains(scanMatchList, v)
		if contains {
			match = true
		}
	}

	if !match {
		return "", false
	}

	return KaskperskyEDR, true
}

//  -----------------------------------------------------------------------
type CylanceDetection struct{}

func (w *CylanceDetection) Name() string {
	return "Cylance Smart Antivirus"
}

func (w *CylanceDetection) Type() EDRType {
	return CylanceEDR
}

var CylanceHeuristic = []string{
	"Cylance\\",
	"Cylance0",
	"Cylance1",
	"Cylance2",
}

func (w *CylanceDetection) Detect(data SystemData) (EDRType, bool) {
	var (
		match bool
	)

	scanMatchList := make([]string, 0)

	for _, v := range data.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, data.Registry.ScanMatch...)

	keywordList := make([]string, 0, len(CylanceHeuristic))
	keywordList = append(keywordList, CylanceHeuristic...)

	for _, v := range keywordList {
		contains := StrSliceContains(scanMatchList, v)
		if contains {
			match = true
		}
	}

	if !match {
		return "", false
	}

	return CylanceEDR, true
}

// ----------------------------------------------------------------
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
	var (
		match bool
	)

	scanMatchList := make([]string, 0)

	for _, v := range data.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, data.Registry.ScanMatch...)

	keywordList := make([]string, 0, len(SymantecHeuristic))
	keywordList = append(keywordList, SymantecHeuristic...)

	for _, v := range keywordList {
		contains := StrSliceContains(scanMatchList, v)
		if contains {
			match = true
		}
	}

	if !match {
		return "", false
	}

	return SymantecEDR, true
}

//----------------------------------------------------------------
type McafeeDetection struct{}

func (w *McafeeDetection) Name() string {
	return "McAfee MVISION Endpoint Detection and Response"
}

func (w *McafeeDetection) Type() EDRType {
	return McafeeEDR
}

var McfeeHeuristic = []string{
	"Mcafee\\",
	"McAfeeAgent\\",
	"APPolicyName",
	"EPPolicyName",
	"OASPolicyName",
}

func (w *McafeeDetection) Detect(data SystemData) (EDRType, bool) {
	var (
		match bool
	)

	scanMatchList := make([]string, 0)

	for _, v := range data.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, data.Registry.ScanMatch...)

	keywordList := make([]string, 0, len(McfeeHeuristic))
	keywordList = append(keywordList, McfeeHeuristic...)

	for _, v := range keywordList {
		contains := StrSliceContains(scanMatchList, v)
		if contains {
			match = true
		}
	}

	if !match {
		return "", false
	}

	return McafeeEDR, true
}

//----------------------------------------------------------------
type CrowdstrikeDetection struct{}

func (w *CrowdstrikeDetection) Name() string {
	return "Crowdstrike EDR Solution"
}

func (w *CrowdstrikeDetection) Type() EDRType {
	return SymantecEDR
}

var CrowdstrikeHeuristic = []string{
	"CrowdStrike",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsDeviceControl.inf",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsFirmwareAnalysis.inf",
}

func (w *CrowdstrikeDetection) Detect(data SystemData) (EDRType, bool) {
	var (
		match bool
	)

	scanMatchList := make([]string, 0)

	for _, v := range data.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range data.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, data.Registry.ScanMatch...)

	keywordList := make([]string, 0, len(CrowdstrikeHeuristic))
	keywordList = append(keywordList, CrowdstrikeHeuristic...)

	for _, v := range keywordList {
		contains := StrSliceContains(scanMatchList, v)
		if contains {
			match = true
		}
	}

	if !match {
		return "", false
	}

	return CrowdstrikeEDR, true
}

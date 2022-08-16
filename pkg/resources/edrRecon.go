package resources

type Recon interface {
	CheckProcesses() ([]ProcessMetaData, error)
	CheckServices() ([]ServiceMetaData, error)
	CheckDrivers() ([]DriverMetaData, error)
	CheckRegistry() (RegistryMetaData, error)
	CheckAVWmiRepo() ([]AVWmiMetaData, error)
	CheckDirectory() (string, error)
}

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

type AVWmiMetaData struct {
	ProductName          string
	ProductGUID          string
	PathToProductExe     string
	ProductExeMetaData   FileMetaData
	PathToReportingExe   string
	ReportingExeMetaData FileMetaData
	ProductState         uint32
	ScanMatch            []string
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
	DriverSysMetaData FileMetaData
	DriverFilePath    string
	ScanMatch         []string
}

type RegistryMetaData struct {
	ScanMatch []string
}

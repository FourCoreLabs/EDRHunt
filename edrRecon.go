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
	ServiceScanMatch   []string
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
	ProcessScanMatch   []string
}

type DriverMetaData struct {
	DriverBaseName    string
	DriverFilePath    string
	DriverSysMetaData FileMetaData
	DriverScanMatch   []string
}

type RegistryMetaData struct {
	RegistryScanMatch []string
}

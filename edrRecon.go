package edrRecon

type Recon interface {
	CheckProcesses() (string, error)
	CheckServices() (string, error)
	CheckDrivers() (string, error)
	CheckRegistry() (string, error)
	CheckDirectory() (string, error)
}

type EdrHunt struct{}

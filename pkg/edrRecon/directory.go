package edrRecon

import "fmt"

func (edr *EdrHunt) CheckDirectory() (string, error) {
	return "", fmt.Errorf("directory scan is not implemented: unnecessarily slow, genrates false positives, also, monitoring command line so, reduntant, again")
}

package resources

import (
	"github.com/FourCoreLabs/EDRHunt/pkg/util"
)

type SystemData struct {
	Processes []ProcessMetaData
	Registry  RegistryMetaData
	Services  []ServiceMetaData
	Drivers   []DriverMetaData
}

// CountMatchesAll collects all the scanned matches of suspicious names and checks for passed keywords in the matches.
func (s *SystemData) CountMatchesAll(keywords ...[]string) (int, bool) {
	var match bool
	var count int

	scanMatchList := make([]string, 0)

	for _, v := range s.Processes {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range s.Services {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	for _, v := range s.Drivers {
		scanMatchList = append(scanMatchList, v.ScanMatch...)
	}

	scanMatchList = append(scanMatchList, s.Registry.ScanMatch...)

	var totalLen int
	for _, v := range keywords {
		totalLen += len(v)
	}
	keywordList := make([]string, 0, totalLen)

	for _, v := range keywords {
		keywordList = append(keywordList, v...)
	}

	for _, v := range keywordList {
		contains := util.StrSliceContains(scanMatchList, v)
		if contains {
			match = true
			count++
		}
	}

	return count, match
}

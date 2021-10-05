package edrRecon

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bi-zone/go-fileversion"
)

var (
	file fileversion.Info
	err  error
)

// crashes at line 334 sometimes.
func GetFileMetaData(filepath string) (FileMetaData, error) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	filepath = strings.Replace(filepath, "\"", "", -1)

	if filepath == "" {
		return FileMetaData{}, errors.New("empty filepath")
	}

	file, err = fileversion.New(filepath)
	if err != nil {
		if strings.HasPrefix(filepath, `c:\windows\system32\`) {
			filepathMod := strings.Replace(filepath, `c\windows\system32`, `c:\Windows\Sysnative`, -1)
			file, err = fileversion.New(filepathMod)
			if err != nil {
				return FileMetaData{}, fmt.Errorf("cannot find resource: %s", filepath)
			}
		}
	}

	// fileInfoStr := fmt.Sprintf("\n\tProductName: %s\n\tOriginalFileName: %s\n\tInternalFileName: %s\n\tCompany Name: %s\n\tFileDescription: %s\n\tProductVersion: %s\n\tComments: %s\n\tLegalCopyright: %s\n\tLegalTrademarks: %s", file.ProductName(), file.OriginalFilename(), file.InternalName(), file.CompanyName(), file.FileDescription(), file.ProductVersion(), file.Comments(), file.LegalCopyright(), file.LegalTrademarks())

	return FileMetaData{
		ProductName:      file.ProductName(),
		OriginalFilename: file.OriginalFilename(),
		InternalFileName: file.InternalName(),
		CompanyName:      file.CompanyName(),
		FileDescription:  file.FileDescription(),
		ProductVersion:   file.ProductVersion(),
		Comments:         file.Comments(),
		LegalCopyright:   file.LegalCopyright(),
		LegalTrademarks:  file.LegalTrademarks(),
	}, nil
}

func FileMetaDataParser(file FileMetaData) string {
	if file.ProductName == "" {
		return ""
	}
	return fmt.Sprintf("\n\tProductName: %s\n\tOriginalFileName: %s\n\tInternalFileName: %s\n\tCompany Name: %s\n\tFileDescription: %s\n\tProductVersion: %s\n\tComments: %s\n\tLegalCopyright: %s\n\tLegalTrademarks: %s", file.ProductName, file.OriginalFilename, file.InternalFileName, file.CompanyName, file.FileDescription, file.ProductVersion, file.Comments, file.LegalCopyright, file.LegalTrademarks)
}

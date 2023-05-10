package edrRecon

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fourcorelabs/edrhunt/pkg/resources"
	"github.com/hashicorp/go-multierror"
	"github.com/yusufpapurcu/wmi"
)

type AntiVirusProduct struct {
	DisplayName              string
	InstanceGuid             string
	PathToSignedProductExe   string
	PathToSignedReportingExe string
	ProductState             uint32
}

type AvResult struct {
	AvProduct []AntiVirusProduct
	Err       error
}

const (
	namespace = "root\\SecurityCenter2"
	class     = "AntiVirusProduct"
	wmiErr    = "wmi query timed out"
)

func CheckAVWmiRepo() ([]resources.AVWmiMetaData, error) {
	var (
		avList   []AntiVirusProduct
		multiErr error
		summary  []resources.AVWmiMetaData = make([]resources.AVWmiMetaData, 0)
		err      error
	)

	avList, err = GetAVwithWMI()
	if err != nil {
		return summary, err
	}
	for _, av := range avList {
		if av.DisplayName == "" {
			continue
		}
		output, err := AnalyzeAVProduct(av)
		if err != nil {
			multiErr = multierror.Append(multiErr, err)
			continue
		}

		if len(output.ScanMatch) > 0 {
			summary = append(summary, output)
		}

	}
	return summary, multiErr
}

func AnalyzeAVProduct(av AntiVirusProduct) (resources.AVWmiMetaData, error) {
	analysis := resources.AVWmiMetaData{
		ProductName:        av.DisplayName,
		ProductGUID:        av.InstanceGuid,
		PathToProductExe:   av.PathToSignedProductExe,
		PathToReportingExe: av.PathToSignedReportingExe,
		ProductState:       av.ProductState,
	}

	if analysis.PathToProductExe != "" {
		analysis.ProductExeMetaData, _ = GetFileMetaData(analysis.PathToProductExe)
	}

	if analysis.PathToReportingExe != "" {
		analysis.ReportingExeMetaData, _ = GetFileMetaData(analysis.PathToReportingExe)
	}

	for _, edr := range EdrList {
		if strings.Contains(
			strings.ToLower(fmt.Sprint(analysis)),
			strings.ToLower(edr)) {
			analysis.ScanMatch = append(analysis.ScanMatch, edr)
		}
	}

	return analysis, nil
}

func GetAVwithWMI() ([]AntiVirusProduct, error) {
	result := make(chan AvResult, 1)
	go func() {
		result <- WMIQuery()
	}()
	select {
	case <-time.After(6 * time.Second):
		return nil, errors.New(wmiErr)
	case result := <-result:
		return result.AvProduct, result.Err
	}

}

func WMIQuery() AvResult {
	var avResults []AntiVirusProduct
	query := wmi.CreateQuery(&avResults, "", class)
	err := wmi.QueryNamespace(query, &avResults, namespace)
	return AvResult{
		AvProduct: avResults,
		Err:       err,
	}
}

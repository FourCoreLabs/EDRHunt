package main

import (
	"errors"
	"time"

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

func WMIQuery() AvResult {
	var avResults []AntiVirusProduct
	query := wmi.CreateQuery(&avResults, "", "AntiVirusProduct")
	err := wmi.QueryNamespace(query, &avResults, "root\\SecurityCenter2")
	return AvResult{
		AvProduct: avResults,
		Err:       err,
	}
}

func GetAVwithWMI() ([]AntiVirusProduct, error) {
	result := make(chan AvResult, 1)
	go func() {
		result <- WMIQuery()
	}()
	select {
	case <-time.After(10 * time.Second):
		return nil, errors.New("wmi query timed out")
	case result := <-result:
		return result.AvProduct, result.Err
	}
}

func main() {
	query, queryErr := GetAVwithWMI()
	if queryErr != nil {
		panic(queryErr)
	}
	for i, v := range query {
		println(i+1, v.DisplayName, v.InstanceGuid, v.PathToSignedProductExe, v.PathToSignedReportingExe, v.ProductState)
	}
}

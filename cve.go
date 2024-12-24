package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func GetSeverityCVE(id string) (string, error) {

	url := fmt.Sprintf("https://cveawg.mitre.org/api/cve/%s", id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var data CveDetail

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "", err
	}

	if len(data.Containers.Cna.Metrics) != 0 {
		return data.Containers.Cna.Metrics[0].CvssV31.BaseSeverity, nil
	}

	if len(data.Containers.Adp) != 0 {
		adp := data.Containers.Adp[0]

		if len(adp.Metrics) != 0 {
			return adp.Metrics[0].CvssV31.BaseSeverity, nil
		}
	}

	return "", nil
}

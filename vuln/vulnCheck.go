package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/born2ngopi/remora/severity"
	"github.com/born2ngopi/remora/table"
	"github.com/born2ngopi/remora/types"
	"golang.org/x/vuln/scan"
)

var (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[37m"
	White   = "\033[97m"
)

func Run(isGitHook bool, critical, high, medium int) {
	fileName, data, err := runVulnCheck()
	if fileName != "" {
		defer os.RemoveAll(fileName)
	}

	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	rows, tLevel, err := normalize(data)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	table.Print(rows)

	if isGitHook {
		var msg []string
		if tLevel.Critical >= critical {
			msg = append(msg, fmt.Sprintf("%d Critical vulnerabilities found", tLevel.Critical))
		}

		if tLevel.High >= high {
			msg = append(msg, fmt.Sprintf("%d High vulnerabilities found", tLevel.High))
		}

		if tLevel.Medium >= medium {
			msg = append(msg, fmt.Sprintf("%d Medium vulnerabilities found", tLevel.Medium))
		}

		if len(msg) > 0 {
			fmt.Println("\033[31m" + strings.Join(msg, " & ") + "\033[0m")
			os.Exit(1)
		}
	}

}

func runVulnCheck() (string, types.VulnCheck, error) {
	ctx := context.Background()

	args := []string{
		"-format=sarif",
		"./...",
	}

	// make output to file
	f, err := os.CreateTemp(".", "vuln-*.json")
	if err != nil {
		return "", types.VulnCheck{}, err
	}

	fileName := f.Name()

	defer f.Close()

	cmd := scan.Command(ctx, args...)
	cmd.Stdout = f

	err = cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	switch err := err.(type) {
	case nil:
	case interface{ ExitCode() int }:
		return fileName, types.VulnCheck{}, fmt.Errorf("exit code: %d", err.ExitCode())
	default:
		return fileName, types.VulnCheck{}, err
	}

	f.Seek(0, 0)
	var data types.VulnCheck
	err = json.NewDecoder(f).Decode(&data)
	return fileName, data, err

}

func normalize(data types.VulnCheck) ([]types.Row, types.TotalLevel, error) {
	var rows []types.Row
	var tLevel types.TotalLevel
	var goCves = make(map[string]string)
	var goGhsa = make(map[string]string)

	for _, run := range data.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			for _, tag := range rule.Properties.Tags {
				// check start with CVE
				if strings.HasPrefix(tag, "CVE") {
					goCves[rule.ID] = tag
				} else if strings.HasPrefix(tag, "GHSA") {
					goGhsa[rule.ID] = tag
				}
			}
		}

		for _, result := range run.Results {

			if result.Level == "note" {
				continue
			}

			var severityStr, link string

			cve, ok := goCves[result.RuleID]
			if ok {
				_severity, err := severity.GetSeverityCVE(cve)
				if err != nil {
					return nil, types.TotalLevel{}, err
				}
				link = fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cve)
				severityStr = _severity
			} else {
				ghsa, ok := goGhsa[result.RuleID]
				if !ok {
					continue
				}

				_severity, err := severity.GetSeverityGHSA(ghsa)
				if err != nil {
					return nil, types.TotalLevel{}, err
				}
				link = fmt.Sprintf("https://github.com/advisories/%s", ghsa)
				severityStr = _severity
			}

			severityStr = strings.ToLower(severityStr)

			row := types.Row{
				RuleId:  result.RuleID,
				Message: result.Message.Text,
				Link:    link,
			}
			switch severityStr {
			case "critical":
				tLevel.Critical++
				row.Level = Red + "Critical" + Reset
			case "high":
				tLevel.High++
				row.Level = Magenta + "high" + Reset
			case "medium":
				tLevel.Medium++
				row.Level = Yellow + "medium" + Reset
			case "low":
				tLevel.Low++
				row.Level = Green + "low" + Reset
			default:
				continue
			}

			rows = append(rows, row)

		}

	}

	return rows, tLevel, nil
}

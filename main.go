package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/vuln/scan"
)

var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var Blue = "\033[34m"
var Magenta = "\033[35m"
var Cyan = "\033[36m"
var Gray = "\033[37m"
var White = "\033[97m"

func main() {

	fileName, data, err := runVulnCheck()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(fileName)

	rows, tLevel, err := normalize(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	Print(rows)

	// check if any argument -githook=true
	if len(os.Args) > 1 && os.Args[1] == "-githook=true" {
		var msg []string
		if tLevel.Critical > 0 {
			msg = append(msg, "Critical vulnerabilities found")
		}

		if tLevel.High > 4 {
			msg = append(msg, "High vulnerabilities found more than 4")
		}

		if tLevel.Medium > 6 {
			msg = append(msg, "High vulnerabilities found more than 6")
		}

		if len(msg) > 0 {
			fmt.Println("\033[31m" + strings.Join(msg, " & ") + "\033[0m")
			os.Exit(1)
		}
	}

}

func runVulnCheck() (string, VulnCheck, error) {
	ctx := context.Background()

	args := []string{
		"-format=sarif",
		"./...",
	}

	// make output to file
	f, err := os.CreateTemp(".", "vuln-*.json")
	if err != nil {
		return "", VulnCheck{}, err
	}

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
		return "", VulnCheck{}, fmt.Errorf("exit code: %d", err.ExitCode())
	default:
		return "", VulnCheck{}, err
	}

	f.Seek(0, 0)
	var data VulnCheck
	err = json.NewDecoder(f).Decode(&data)
	return "", data, err

}

func normalize(data VulnCheck) ([]Row, totalLevel, error) {
	var rows []Row
	var tLevel totalLevel
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

			var severity, link string

			cve, ok := goCves[result.RuleID]
			if ok {
				_severity, err := GetSeverityCVE(cve)
				if err != nil {
					return nil, totalLevel{}, err
				}
				link = fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cve)
				severity = _severity
			} else {
				ghsa, ok := goGhsa[result.RuleID]
				if !ok {
					continue
				}

				_severity, err := GetSeverityGHSA(ghsa)
				if err != nil {
					return nil, totalLevel{}, err
				}
				link = fmt.Sprintf("https://github.com/advisories/%s", ghsa)
				severity = _severity
			}

			severity = strings.ToLower(severity)

			row := Row{
				ruleId:  result.RuleID,
				message: result.Message.Text,
				link:    link,
			}
			switch severity {
			case "critical":
				tLevel.Critical++
				row.level = Red + "Critical" + Reset
			case "high":
				tLevel.High++
				row.level = Magenta + "high" + Reset
			case "medium":
				tLevel.Medium++
				row.level = Yellow + "medium" + Reset
			case "low":
				tLevel.Low++
				row.level = Green + "low" + Reset
			default:
				continue
			}

			rows = append(rows, row)

		}

	}

	return rows, tLevel, nil
}

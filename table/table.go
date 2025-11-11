package table

import (
	"os"

	"github.com/born2ngopi/remora/types"
	goTable "github.com/jedib0t/go-pretty/v6/table"
)

func Print(isToCsv bool, datas []types.Row) {

	var (
		id = 1
	)

	t := goTable.NewWriter()
	t.SetOutputMirror(os.Stdout)
	if isToCsv {
		t.AppendHeader(goTable.Row{"#", "Vuln Report", "Severity", "Found In", "Fixed In", "Message", "Link To Detail"})
	} else {
		t.AppendHeader(goTable.Row{"#", "Vuln Report", "Severity", "Found In", "Fixed In", "Link To Detail"})
	}

	for _, data := range datas {

		if isToCsv {
			t.AppendRow(goTable.Row{id, data.RuleId, data.Level, data.Found, data.Fix, data.Message, data.Link})
		} else {
			t.AppendRow(goTable.Row{id, data.RuleId, data.Level, data.Found, data.Fix, data.Link})
		}

		id++
	}

	t.AppendSeparator()
	t.AppendFooter(goTable.Row{"", "", "Total", id - 1, ""})
	if isToCsv {

		// set output to csv
		f, _ := os.Create("remora-report.csv")
		defer f.Close()
		t.SetOutputMirror(f)
		t.RenderCSV()
	} else {
		t.Render()
	}

}

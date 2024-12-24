package main

import (
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
)

type Row struct {
	ruleId  string
	level   string
	message string
	link    string
}

func Print(datas []Row) {

	var rows []table.Row

	var (
		id = 1
	)
	for _, data := range datas {
		rows = append(rows, table.Row{id, data.ruleId, data.level, data.message, data.link})
		id++
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"#", "Vuln Report", "Severity", "Message", "Link To Detail"})
	t.AppendRows(rows)
	t.AppendSeparator()
	t.AppendFooter(table.Row{"", "", "Total", len(rows), ""})
	t.Render()

}

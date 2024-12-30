package table

import (
	"os"

	"github.com/born2ngopi/remora/types"
	"github.com/jedib0t/go-pretty/v6/table"
)

func Print(datas []types.Row) {

	var rows []table.Row

	var (
		id = 1
	)
	for _, data := range datas {
		rows = append(rows, table.Row{id, data.RuleId, data.Level, data.Message, data.Link})
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

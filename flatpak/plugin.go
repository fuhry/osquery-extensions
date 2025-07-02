package flatpak

import (
	"context"

	"github.com/osquery/osquery-go/plugin/table"
)

const (
	ColumnID      = "id"
	ColumnType    = "type"
	ColumnName    = "name"
	ColumnVersion = "version"
	ColumnHash    = "hash"
	ColumnBranch  = "branch"
	ColumnUser    = "user"
)

func Schema() (out []table.ColumnDefinition) {
	return []table.ColumnDefinition{
		table.TextColumn(ColumnID),
		table.TextColumn(ColumnType),
		table.TextColumn(ColumnName),
		table.TextColumn(ColumnVersion),
		table.TextColumn(ColumnHash),
		table.TextColumn(ColumnBranch),
		table.TextColumn(ColumnUser),
	}
}

func Generate(ctx context.Context, q table.QueryContext) (out []map[string]string, err error) {
	for _, pkg := range Packages() {
		out = append(out, map[string]string{
			ColumnID:      pkg.Id(),
			ColumnType:    string(pkg.Type()),
			ColumnName:    pkg.Name(),
			ColumnVersion: pkg.Version(),
			ColumnHash:    pkg.Hash(),
			ColumnBranch:  pkg.Branch(),
			ColumnUser:    pkg.User(),
		})
	}
	return out, err
}

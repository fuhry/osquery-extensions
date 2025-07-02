package pacman

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"sync"

	"github.com/Jguer/go-alpm/v2"
	"github.com/osquery/osquery-go/plugin/table"
)

const (
	ColumnName         = "name"
	ColumnVersion      = "version"
	ColumnDescription  = "description"
	ColumnArchitecture = "arch"
	ColumnUrl          = "url"
	ColumnLicense      = "license"
	ColumnSize         = "size"
	ColumnExplicit     = "explicit"

	ColumnPackage = "package"
	ColumnPath    = "path"
)

var (
	h      *alpm.Handle
	hMu    sync.Mutex
	dbPath string = "/var/lib/pacman"
)

var packagesColumns = []columnDef[alpm.IPackage]{
	stringColumn[alpm.IPackage]{ColumnName, func(p alpm.IPackage) string { return p.Name() }},
	stringColumn[alpm.IPackage]{ColumnVersion, func(p alpm.IPackage) string { return p.Version() }},
	stringColumn[alpm.IPackage]{ColumnDescription, func(p alpm.IPackage) string { return p.Description() }},
	stringColumn[alpm.IPackage]{ColumnArchitecture, func(p alpm.IPackage) string { return p.Architecture() }},
	stringColumn[alpm.IPackage]{ColumnUrl, func(p alpm.IPackage) string { return p.URL() }},
	stringColumn[alpm.IPackage]{ColumnLicense, func(p alpm.IPackage) string { return strings.Join(p.Licenses().Slice(), ",") }},
	intColumn[alpm.IPackage]{ColumnSize, func(p alpm.IPackage) int64 { return p.ISize() }},
	boolColumn[alpm.IPackage]{ColumnExplicit, func(p alpm.IPackage) bool { return p.Reason() == alpm.PkgReasonExplicit }},
}

type filesColumnsCtx = struct {
	p alpm.IPackage
	f alpm.File
}

var filesColumns = []columnDef[filesColumnsCtx]{
	stringColumn[filesColumnsCtx]{ColumnPackage, func(c filesColumnsCtx) string { return c.p.Name() }},
	stringColumn[filesColumnsCtx]{ColumnPath, func(c filesColumnsCtx) string { return c.f.Name }},
	intColumn[filesColumnsCtx]{ColumnSize, func(c filesColumnsCtx) int64 { return c.f.Size }},
}

// PackagesSchema returns the schema for the "pacman_packages" table.
func PackagesSchema() (out []table.ColumnDefinition) {
	for _, c := range packagesColumns {
		out = append(out, c.def())
	}
	return
}

// PackagesGenerate generates row data for the "pacman_packages" table.
func PackagesGenerate(ctx context.Context, q table.QueryContext) ([]map[string]string, error) {
	h, err := handle()
	if err != nil {
		return nil, err
	}
	defer release()

	db, err := h.LocalDB()
	if err != nil {
		return nil, err
	}

	var out []map[string]string
	err = db.PkgCache().ForEach(func(pkg alpm.IPackage) error {
		row := make(map[string]string)
		for _, col := range packagesColumns {
			if constraints, ok := q.Constraints[col.name()]; ok {
				if m, err := col.matches(pkg, constraints); !m {
					return err
				}
			}
			rawValue := col.val(pkg)
			switch v := rawValue.(type) {
			case string:
				row[col.name()] = v
			case int, int64, uint, uint64:
				row[col.name()] = fmt.Sprintf("%d", v)
			case bool:
				row[col.name()] = "0"
				if v {
					row[col.name()] = "1"
				}
			}
		}
		out = append(out, row)
		return nil
	})

	return out, err
}

// FilesSchema returns the schema for the "pacman_files" table.
func FilesSchema() (out []table.ColumnDefinition) {
	for _, c := range filesColumns {
		out = append(out, c.def())
	}
	return
}

// FilesGenerate generates row data for the "pacman_files" table.
func FilesGenerate(ctx context.Context, q table.QueryContext) ([]map[string]string, error) {
	h, err := handle()
	if err != nil {
		return nil, err
	}
	defer release()

	db, err := h.LocalDB()
	if err != nil {
		return nil, err
	}

	var out []map[string]string
	err = db.PkgCache().ForEach(func(pkg alpm.IPackage) error {
		// filter on package name before iterating the files, which is computationally expensive
		if c, ok := q.Constraints[ColumnPackage]; ok {
			if m, err := filesColumns[0].matches(filesColumnsCtx{pkg, alpm.File{}}, c); !m {
				return err
			}
		}

		for _, f := range pkg.Files() {
			row := make(map[string]string)
			for i, col := range filesColumns {
				ctx := filesColumnsCtx{pkg, f}
				// skip filtering on the `package` column, we did this above before iterating Files
				if i > 0 {
					if constraints, ok := q.Constraints[col.name()]; ok {
						if m, err := col.matches(ctx, constraints); !m {
							return err
						}
					}
				}
				rawValue := col.val(ctx)
				switch v := rawValue.(type) {
				case string:
					row[col.name()] = v
				case int, int64, uint, uint64:
					row[col.name()] = fmt.Sprintf("%d", v)
				case bool:
					row[col.name()] = "0"
					if v {
						row[col.name()] = "1"
					}
				}
			}
			out = append(out, row)
		}
		return nil
	})

	return out, err
}

func handle() (*alpm.Handle, error) {
	var err error

	hMu.Lock()
	defer hMu.Unlock()

	if h != nil {
		return h, nil
	}

	h, err = alpm.Initialize("/", dbPath)
	return h, err
}

func release() {
	hMu.Lock()
	defer hMu.Unlock()

	if h == nil {
		return
	}

	h.Release()
	h = nil
}

func init() {
	flag.StringVar(&dbPath, "pacman.db-path", dbPath, "path to pacman database")
}

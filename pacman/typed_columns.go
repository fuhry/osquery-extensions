package pacman

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Jguer/go-alpm/v2"
	"github.com/osquery/osquery-go/plugin/table"
	"go.fuhry.dev/osquery/extcommon"
)

// TODO:
// - make these interfaces public and move to extcommon
// - support the LIKE operator

type columnDef[T any] interface {
	name() string
	def() table.ColumnDefinition
	val(ctx T) any
	matches(T, table.ConstraintList) (bool, error)
}

type stringColumn[T any] struct {
	n   string
	get func(T) string
}

type intColumn[T any] struct {
	n   string
	get func(T) int64
}

type boolColumn[T any] struct {
	n   string
	get func(T) bool
}

func (sc stringColumn[T]) name() string { return sc.n }

func (sc stringColumn[T]) val(ctx T) any {
	return sc.get(ctx)
}

func (sc stringColumn[T]) def() table.ColumnDefinition {
	return table.TextColumn(sc.name())
}

func (sc stringColumn[T]) matches(ctx T, constraints table.ConstraintList) (bool, error) {
	if constraints.Affinity != table.ColumnTypeText {
		return false, fmt.Errorf("unable to process constraint: column %q is a text column", sc.name())
	}
	val := sc.get(ctx)
	for _, c := range constraints.Constraints {
		switch c.Operator {
		case table.OperatorEquals:
			return val == c.Expression, nil
		case table.OperatorGreaterThan:
			return alpm.VerCmp(val, c.Expression) < 0, nil
		case table.OperatorGreaterThanOrEquals:
			return val == c.Expression || alpm.VerCmp(val, c.Expression) < 0, nil
		case table.OperatorLessThan:
			return alpm.VerCmp(c.Expression, val) < 0, nil
		case table.OperatorLessThanOrEquals:
			return val == c.Expression || alpm.VerCmp(c.Expression, val) < 0, nil
		case table.OperatorGlob:
			g, err := extcommon.CompileGlob(c.Expression)
			if err != nil {
				return false, err
			}
			return g.Match(val), nil
		case table.OperatorRegexp:
			r, err := extcommon.CompileRegexp(c.Expression)
			if err != nil {
				return false, err
			}
			return r.MatchString(val), nil
		default:
			return false, fmt.Errorf("unsupported operator: %v", c.Operator)
		}
	}

	// if no constraints, return true
	return true, nil
}

func (ic intColumn[T]) name() string { return ic.n }

func (ic intColumn[T]) val(p T) any {
	return ic.get(p)
}

func (ic intColumn[T]) def() table.ColumnDefinition {
	return table.BigIntColumn(ic.name())
}

func (ic intColumn[T]) matches(ctx T, constraints table.ConstraintList) (bool, error) {
	if constraints.Affinity != table.ColumnTypeInteger && constraints.Affinity != table.ColumnTypeBigInt {
		return false, fmt.Errorf("unable to process constraint: column %q is an integer column", ic.name())
	}
	val := ic.get(ctx)
	for _, c := range constraints.Constraints {
		i, err := strconv.Atoi(c.Expression)
		if err != nil {
			return false, err
		}
		exprInt := int64(i)
		switch c.Operator {
		case table.OperatorEquals:
			return val == exprInt, nil
		case table.OperatorGreaterThan:
			return val > exprInt, nil
		case table.OperatorGreaterThanOrEquals:
			return val >= exprInt, nil
		case table.OperatorLessThan:
			return val < exprInt, nil
		case table.OperatorLessThanOrEquals:
			return val <= exprInt, nil
		default:
			return false, fmt.Errorf("unsupported operator: %v", c.Operator)
		}
	}

	// if no constraints, return true
	return true, nil
}

func (bc boolColumn[T]) name() string { return bc.n }

func (bc boolColumn[T]) val(ctx T) any {
	if bc.get(ctx) {
		return 1
	}
	return 0
}

func (bc boolColumn[T]) def() table.ColumnDefinition {
	return table.IntegerColumn(bc.name())
}

func (bc boolColumn[T]) matches(ctx T, constraints table.ConstraintList) (bool, error) {
	val := bc.get(ctx)
	for _, c := range constraints.Constraints {
		e, err := parseTruthy(c.Expression)
		if err != nil {
			return false, err
		}
		switch c.Operator {
		case table.OperatorEquals:
			return val == e, nil
		default:
			return false, fmt.Errorf("unsupported operator: %v", c.Operator)
		}
	}

	// if no constraints, return true
	return true, nil
}

func parseTruthy(val string) (bool, error) {
	switch strings.ToLower(val) {
	case "yes", "true", "1":
		return true, nil
	case "no", "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("not a truthy value: %q", val)
}

package portal

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	p "github.com/lab47/peggysue"
	"github.com/lab47/peggysue/toolkit"
)

type probeExpr struct {
	kind, text string
	items      []probeExpr
	keys       []string
}

type probeStatement struct {
	name   string
	groups []probeExpr
	value  probeExpr
	local  bool
}

type probeReport struct {
	kind, duration, table, sort, limit string
	clear, stop                        bool
}

type probeProgram struct {
	selector   string
	conditions []queryCondition
	statements []probeStatement
	reports    []probeReport
}

var probeGrammar = newProbeGrammar()

func newProbeGrammar() p.Rule {
	token := toolkit.After(toolkit.WS)
	sym := func(s string) p.Rule { return token(p.S(s)) }
	id := token(p.Capture(p.Re(`[A-Za-z_][A-Za-z_0-9.]*`)))
	word := token(p.Capture(p.Re(`(?:[A-Za-z_][A-Za-z_0-9.:]*|:[A-Za-z_][A-Za-z_0-9]*|-?[0-9][A-Za-z_0-9.]*)`)))
	kw := func(s string) p.Rule { return token(p.Seq(p.S(s), p.Not(p.Re(`[A-Za-z_0-9.]`)))) }
	expr := p.R("probe-expression")
	collect := func(v []any) any {
		out := make([]probeExpr, len(v))
		for i := range v {
			out[i] = v[i].(probeExpr)
		}
		return out
	}
	list := func(open, close string) p.Rule {
		return p.Action(p.Seq(sym(open), p.Named("items", p.Maybe(p.Action(p.Seq(p.Named("first", expr), p.Named("rest", p.Many(p.Seq(sym(","), expr), 0, -1, collect))), func(v p.Values) any {
			return append([]probeExpr{v.Get("first").(probeExpr)}, v.Get("rest").([]probeExpr)...)
		}))), sym(close)), func(v p.Values) any {
			e := probeExpr{kind: "list"}
			if x := v.Get("items"); x != nil {
				e.items = x.([]probeExpr)
			}
			return e
		})
	}
	entry := p.Action(p.Seq(p.Named("key", id), sym(":"), p.Named("value", expr)), func(v p.Values) any {
		return probeExpr{keys: []string{v.Get("key").(string)}, items: []probeExpr{v.Get("value").(probeExpr)}}
	})
	entries := p.Action(p.Seq(p.Named("first", entry), p.Named("rest", p.Many(p.Seq(sym(","), entry), 0, -1, collect))), func(v p.Values) any {
		return append([]probeExpr{v.Get("first").(probeExpr)}, v.Get("rest").([]probeExpr)...)
	})
	dict := p.Action(p.Seq(sym("{"), p.Named("entries", entries), sym("}")), func(v p.Values) any {
		e := probeExpr{kind: "object"}
		for _, pair := range v.Get("entries").([]probeExpr) {
			e.keys = append(e.keys, pair.keys[0])
			e.items = append(e.items, pair.items[0])
		}
		return e
	})
	call := p.Action(p.Seq(p.Named("function", id), sym("("), p.Named("args", p.Maybe(p.Or(entries, p.Action(p.Seq(p.Named("first", expr), p.Named("rest", p.Many(p.Seq(sym(","), expr), 0, -1, collect))), func(v p.Values) any {
		return append([]probeExpr{v.Get("first").(probeExpr)}, v.Get("rest").([]probeExpr)...)
	})))), sym(")")), func(v p.Values) any {
		e := probeExpr{kind: "call", text: v.Get("function").(string)}
		if args := v.Get("args"); args != nil {
			for _, arg := range args.([]probeExpr) {
				if len(arg.keys) != 0 {
					e.keys = append(e.keys, arg.keys[0])
					e.items = append(e.items, arg.items[0])
				} else {
					e.items = append(e.items, arg)
				}
			}
		}
		return e
	})
	quoted := token(p.Transform(p.Re(`"(?:[^"\\]|\\["\\])*"`), func(s string) any {
		text, err := strconv.Unquote(s)
		if err != nil {
			return probeExpr{kind: "invalid"}
		}
		return probeExpr{kind: "string", text: text}
	}))
	atom := p.Action(p.Named("value", word), func(v p.Values) any { return probeExpr{kind: "atom", text: v.Get("value").(string)} })
	expr.Set(p.Or(call, list("[", "]"), dict, quoted, atom))
	condition := p.Action(p.Seq(p.Named("field", id), p.Named("op", p.Or(p.Transform(kw("in"), func(string) any { return "in" }), p.Transform(p.Or(sym("=="), sym("=")), func(string) any { return "=" }))), p.Named("value", p.Or(list("(", ")"), expr))), func(v p.Values) any {
		e := v.Get("value").(probeExpr)
		values := []string{e.text}
		if e.kind == "list" {
			values = nil
			for _, item := range e.items {
				if item.kind != "atom" && item.kind != "string" {
					values = nil
					break
				}
				values = append(values, item.text)
			}
		}
		// Unsupported predicate expressions are rejected rather than interpreted.
		if e.kind != "atom" && e.kind != "string" && e.kind != "list" {
			values = nil
		}
		if e.kind == "list" && v.Get("op").(string) == "=" {
			values = nil
		}
		return queryCondition{field: queryField(v.Get("field").(string)), op: v.Get("op").(string), values: values}
	})
	conditions := p.Action(p.Seq(kw("where"), p.Named("first", condition), p.Named("rest", p.Many(p.Seq(kw("and"), condition), 0, -1, func(v []any) any {
		out := []queryCondition{}
		for _, x := range v {
			out = append(out, x.(queryCondition))
		}
		return out
	}))), func(v p.Values) any {
		return append([]queryCondition{v.Get("first").(queryCondition)}, v.Get("rest").([]queryCondition)...)
	})
	local := p.Action(p.Seq(kw("let"), p.Named("name", id), sym("="), p.Named("value", expr)), func(v p.Values) any {
		return probeStatement{name: v.Get("name").(string), value: v.Get("value").(probeExpr), local: true}
	})
	table := p.Action(p.Seq(sym("@"), p.Named("name", id), p.Named("groups", list("[", "]")), sym("="), p.Named("value", expr)), func(v p.Values) any {
		return probeStatement{name: v.Get("name").(string), groups: v.Get("groups").(probeExpr).items, value: v.Get("value").(probeExpr)}
	})
	// Use an action so the optional ordering retains the column, not keyword.
	order := p.Action(p.Seq(kw("order"), kw("by"), p.Named("field", id), kw("desc")), func(v p.Values) any { return v.Get("field") })
	emit := p.Action(p.Seq(kw("emit"), sym("@"), p.Named("table", id), p.Named("sort", p.Maybe(order)), p.Named("limit", p.Maybe(p.Seq(kw("limit"), word)))), func(v p.Values) any {
		r := probeReport{table: v.Get("table").(string)}
		if x := v.Get("sort"); x != nil {
			r.sort = x.(string)
		}
		if x := v.Get("limit"); x != nil {
			r.limit = x.(string)
		}
		return r
	})
	clear := p.Seq(kw("clear"), sym("@"), id)
	report := p.Action(p.Seq(p.Named("kind", p.Or(p.Transform(kw("after"), func(string) any { return "after" }), p.Transform(kw("every"), func(string) any { return "every" }))), p.Named("duration", word), sym("{"), p.Named("action", p.Or(emit, p.Transform(kw("stop"), func(string) any { return probeReport{stop: true} }))), p.Maybe(sym(";")), p.Named("clear", p.Maybe(clear)), p.Maybe(sym(";")), sym("}")), func(v p.Values) any {
		r := v.Get("action").(probeReport)
		r.kind, r.duration = v.Get("kind").(string), v.Get("duration").(string)
		if x := v.Get("clear"); x != nil {
			if r.stop {
				r.stop = false
			}
			r.clear = x.(string) == r.table
			if !r.clear {
				r.table = ""
			}
		}
		return r
	})
	statement := p.Action(p.Seq(p.Named("statement", p.Or(local, table)), p.Maybe(sym(";"))), func(v p.Values) any { return v.Get("statement") })
	return p.Action(p.Seq(toolkit.WS, p.Named("selector", word), p.Named("where", p.Maybe(conditions)), sym("{"), p.Named("statements", p.Many(statement, 1, -1, func(v []any) any {
		out := []probeStatement{}
		for _, x := range v {
			out = append(out, x.(probeStatement))
		}
		return out
	})), sym("}"), p.Named("reports", p.Many(report, 1, 2, func(v []any) any {
		out := []probeReport{}
		for _, x := range v {
			out = append(out, x.(probeReport))
		}
		return out
	})), toolkit.WS, p.EOS()), func(v p.Values) any {
		out := probeProgram{selector: v.Get("selector").(string), statements: v.Get("statements").([]probeStatement), reports: v.Get("reports").([]probeReport)}
		if x := v.Get("where"); x != nil {
			out.conditions = x.([]queryCondition)
		}
		return out
	})
}

func parseProbeQuery(text string) (MonitorRequest, error) {
	v, ok, err := p.New().Parse(probeGrammar, text, p.WithErrors())
	if err != nil {
		return MonitorRequest{}, err
	}
	if !ok {
		return MonitorRequest{}, errors.New("invalid selector/action query")
	}
	return compileProbe(v.(probeProgram))
}

func compileProbe(program probeProgram) (MonitorRequest, error) {
	parts := strings.Split(program.selector, ":")
	parsed := parsedMonitorQuery{source: parts[0], conditions: program.conditions, aggregation: &AggregationRequest{Compact: true}}
	if len(parts) > 1 {
		switch {
		case (parts[0] == "syscalls" || parts[0] == "disk") && len(parts) == 2:
			parsed.conditions = append(parsed.conditions, queryCondition{"phase", "=", []string{parts[1]}})
		case parts[0] == "process" && len(parts) == 2:
			parsed.conditions = append(parsed.conditions, queryCondition{"action", "=", []string{parts[1]}})
		case parts[0] == "tracepoint" && len(parts) == 3:
			parsed.conditions = append(parsed.conditions, queryCondition{"event", "=", []string{parts[1] + ":" + parts[2]}})
		default:
			return MonitorRequest{}, errors.New("unsupported probe selector")
		}
	}
	for _, c := range parsed.conditions {
		if len(c.values) == 0 {
			return MonitorRequest{}, errors.New("predicate requires scalar values or a nonempty scalar list")
		}
		if c.field == "stacks" || c.field == "paths" || c.field == "phase" && len(parts) == 1 {
			return MonitorRequest{}, errors.New("capture controls belong in the selector/action, not where")
		}
	}
	a := parsed.aggregation
	locals := make(map[string]string)
	aliases := make(map[string]string)
	paths, user, kernel := false, false, false
	var resolve func(probeExpr) (string, error)
	resolve = func(e probeExpr) (string, error) {
		if e.kind == "atom" {
			if field, ok := locals[e.text]; ok {
				return field, nil
			}
			if e.text == "file.path" || e.text == "file.dir" {
				paths = true
			}
			return queryField(e.text), nil
		}
		if e.kind != "call" {
			return "", errors.New("grouping requires a field, local projection or supported capture function")
		}
		switch e.text {
		case "path.prefix":
			if len(e.keys) != 0 || len(e.items) != 2 || e.items[0].kind != "atom" || e.items[0].text != "file.path" || e.items[1].kind != "atom" {
				return "", errors.New("path.prefix requires (file.path, DEPTH)")
			}
			paths = true
			parsed.conditions = append(parsed.conditions, queryCondition{"file.depth", "=", []string{e.items[1].text}})
			return "file.dir", nil
		case "stack.user", "stack.kernel":
			prefix := "user.stack"
			if e.text == "stack.user" {
				user = true
			} else {
				kernel = true
				prefix = "kernel.stack"
			}
			if len(e.keys) != len(e.items) {
				return "", errors.New("stack capture accepts named options only")
			}
			for i, key := range e.keys {
				option := e.items[i]
				values, op := []string{option.text}, "="
				if option.kind == "list" {
					if key != "from" {
						return "", errors.New("only stack from accepts alternatives")
					}
					values, op = nil, "in"
					for _, item := range option.items {
						value, err := probePattern(item)
						if err != nil {
							return "", err
						}
						values = append(values, value)
					}
				} else if key == "from" || key == "until" {
					value, err := probePattern(option)
					if err != nil {
						return "", err
					}
					values = []string{value}
				} else if option.kind != "atom" {
					return "", errors.New("stack option requires a scalar")
				}
				parsed.conditions = append(parsed.conditions, queryCondition{prefix + "." + key, op, values})
			}
			return prefix, nil
		default:
			return "", fmt.Errorf("unsupported action function %q", e.text)
		}
	}
	table := ""
	for _, statement := range program.statements {
		if statement.local {
			if !tracepointIdentifier.MatchString(statement.name) || locals[statement.name] != "" || table != "" {
				return MonitorRequest{}, errors.New("locals must be unique identifiers defined before the table")
			}
			field, err := resolve(statement.value)
			if err != nil {
				return MonitorRequest{}, err
			}
			locals[statement.name] = field
			continue
		}
		if table != "" || !tracepointIdentifier.MatchString(statement.name) {
			return MonitorRequest{}, errors.New("one named aggregate table is supported per probe")
		}
		table = statement.name
		for _, group := range statement.groups {
			field, err := resolve(group)
			if err != nil {
				return MonitorRequest{}, err
			}
			a.GroupBy = append(a.GroupBy, field)
			if locals[group.text] != "" {
				aliases[field] = group.text
			}
		}
		metrics := statement.value
		if metrics.kind != "object" {
			metrics = probeExpr{kind: "object", keys: []string{"value"}, items: []probeExpr{metrics}}
		}
		for i, metric := range metrics.items {
			if metric.kind != "call" || len(metric.keys) != 0 {
				return MonitorRequest{}, errors.New("table values must be aggregate function calls")
			}
			m := AggregateMetric{Name: metrics.keys[i], Function: metric.text}
			want := 1
			if metric.text == "count" {
				want = 0
			} else if metric.text == "percentile" {
				want = 2
			}
			if len(metric.items) != want {
				return MonitorRequest{}, fmt.Errorf("wrong argument count for %s", metric.text)
			}
			if want != 0 {
				field, err := resolve(metric.items[0])
				if err != nil {
					return MonitorRequest{}, err
				}
				m.Field = field
			}
			if want == 2 {
				var err error
				m.Percentile, err = strconv.ParseFloat(metric.items[1].text, 64)
				if err != nil {
					return MonitorRequest{}, err
				}
			}
			a.Metrics = append(a.Metrics, m)
		}
	}
	if table == "" {
		return MonitorRequest{}, errors.New("aggregate table required")
	}
	a.Table, a.GroupAliases = table, aliases
	if paths {
		parsed.conditions = append(parsed.conditions, queryCondition{"paths", "=", []string{"true"}})
	}
	if user || kernel {
		stacks := "user"
		if kernel {
			stacks = "kernel"
		}
		if user && kernel {
			stacks = "both"
		}
		parsed.conditions = append(parsed.conditions, queryCondition{"stacks", "=", []string{stacks}})
	}
	for _, report := range program.reports {
		d, err := time.ParseDuration(report.duration)
		if err != nil || d <= 0 {
			return MonitorRequest{}, errors.New("report duration must be positive")
		}
		if report.kind == "after" {
			if a.Window != 0 {
				return MonitorRequest{}, errors.New("duplicate after block")
			}
			a.Window = d
		} else {
			if a.ReportEvery != 0 {
				return MonitorRequest{}, errors.New("duplicate every block")
			}
			a.ReportEvery = d
		}
		if report.stop {
			if report.kind != "after" || report.clear {
				return MonitorRequest{}, errors.New("stop requires an after block")
			}
			continue
		}
		if report.table != table || (report.kind == "every" && !report.clear) || (report.kind == "after" && report.clear) {
			return MonitorRequest{}, errors.New("emit must name the table; every requires clear of that table")
		}
		if report.sort != "" {
			found := false
			for i, m := range a.Metrics {
				if m.Name == report.sort {
					a.SortMetric, found = i, true
				}
			}
			if !found {
				return MonitorRequest{}, errors.New("order by must name a metric")
			}
		}
		if report.limit != "" {
			a.Limit, err = strconv.Atoi(report.limit)
			if err != nil || a.Limit <= 0 {
				return MonitorRequest{}, errors.New("limit must be a positive integer")
			}
		}
	}
	if a.ReportEvery != 0 {
		if len(program.reports) != 2 || program.reports[0].kind != "every" || !program.reports[1].stop {
			return MonitorRequest{}, errors.New("periodic reports require every { emit; clear } followed by after { stop }")
		}
	} else if len(program.reports) != 1 || program.reports[0].stop {
		return MonitorRequest{}, errors.New("one-shot report requires after { emit }")
	}
	r, err := compileMonitorQuery(parsed)
	if err != nil {
		return MonitorRequest{}, err
	}
	fields, _, err := aggregateFields(r)
	if err != nil {
		return MonitorRequest{}, err
	}
	for _, field := range locals {
		valid := false
		for _, allowed := range fields {
			if field == allowed {
				valid = true
				break
			}
		}
		if !valid {
			return MonitorRequest{}, fmt.Errorf("local references unknown field %q", field)
		}
	}
	return r, nil
}

func probePattern(e probeExpr) (string, error) {
	if e.kind == "string" && !strings.HasPrefix(e.text, "*") && !strings.HasSuffix(e.text, "*") && e.text != "" {
		return e.text, nil
	}
	if e.kind == "call" && e.text == "glob" && len(e.keys) == 0 && len(e.items) == 1 && e.items[0].kind == "string" && validEdgeGlob(e.items[0].text) {
		return e.items[0].text, nil
	}
	return "", errors.New("stack pattern requires a literal quoted name or glob(\"prefix*\"); edge stars in literal names are unsupported")
}

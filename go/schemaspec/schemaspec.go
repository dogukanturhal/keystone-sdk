// SPDX-License-Identifier: Apache-2.0

// Package schemaspec converts a drift.Snapshot (the canonicalised
// structural shape of a live PostgreSQL schema) into a Keystone
// SchemaDefinitionSpec (the declarative desired-state model the differ
// consumes).
//
// It is the inverse of the differ: drift.Inspector reads a database into
// a Snapshot, schemaspec.FromSnapshot lifts that Snapshot into a
// SchemaDefinitionSpec, and declarative.Diff turns a (Snapshot, Spec)
// pair back into SQL. Pulling the conversion into the SDK (rather than
// leaving it in keystonectl's main package) lets every "from a database"
// author workflow — `keystonectl inspect`, `keystonectl scaffold`, and
// the sql://-/db://-backed desired-state loaders in package schemasource
// — share one faithful, well-tested implementation.
//
// The conversion is pure: no I/O, no database, no Kubernetes API. All
// parsing operates on the catalog-derived DDL strings already captured
// in the Snapshot (pg_get_constraintdef, pg_get_indexdef,
// pg_get_functiondef output).
package schemaspec

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Options tunes how a Snapshot is projected into a SchemaDefinitionSpec.
//
// SchemaRef and SelectorLabels are mutually exclusive in a valid
// SchemaDefinition (the SD admission webhook rejects an object that sets
// both); callers that intend to emit an apply-able CR should set at most
// one. FromSnapshot does not enforce the exclusivity — it faithfully
// copies whatever the caller asks for so callers retain control over the
// validation surface.
type Options struct {
	// SchemaRef populates spec.schemaRef (single-target form), naming the
	// DatabaseSchema CR this SchemaDefinition manages.
	SchemaRef string

	// SelectorLabels populates spec.schemaSelector.matchLabels (fan-out
	// form), selecting many DatabaseSchemas by label.
	SelectorLabels map[string]string
}

// FromSnapshot projects a drift.Snapshot into a SchemaDefinitionSpec.
//
// Every structural object the inspector captures is carried across:
// base tables (columns, primary keys, unique and CHECK constraints,
// foreign keys, indexes, RLS), enums, sequences, views, functions, RLS
// policies, triggers, and materialized views.
//
// The indexes PostgreSQL creates to back a PRIMARY KEY or UNIQUE
// constraint are dropped, because they are not independent objects —
// they cannot be dropped on their own, and re-emitting one would
// duplicate the constraint it belongs to. They are identified by
// matching the constraint's name, which PostgreSQL always gives the
// backing index.
//
// The result is the desired-state model that, when diffed against an
// empty schema, reproduces the inspected schema as CREATE DDL — the
// basis for scaffold's adoption baseline.
func FromSnapshot(snap *drift.Snapshot, opts Options) *keystonev1alpha1.SchemaDefinitionSpec {
	spec := &keystonev1alpha1.SchemaDefinitionSpec{}
	if snap == nil {
		return spec
	}
	if opts.SchemaRef != "" {
		spec.SchemaRef = opts.SchemaRef
	}
	if len(opts.SelectorLabels) > 0 {
		spec.SchemaSelector = &metav1.LabelSelector{
			MatchLabels: opts.SelectorLabels,
		}
	}

	for _, x := range snap.Extensions {
		ext := keystonev1alpha1.DesiredExtension{Name: x.Name}
		// Only pin the schema when the extension deliberately lives somewhere
		// other than the schema being inspected. A sql:// desired source is
		// normalised by applying it to a content-hash-named scratch schema, so
		// an extension created by that source reports the scratch name — and
		// pinning it would write a throwaway identifier into the migration.
		if x.Schema != "" && x.Schema != snap.Schema {
			ext.Schema = x.Schema
		}
		spec.Extensions = append(spec.Extensions, ext)
	}

	// Index constraints by table for PK/FK extraction.
	pkByTable := map[string][]string{}   // table → PK column list
	pkNameByTable := map[string]string{} // table → PK constraint name
	// table → names of indexes that exist only to back a PRIMARY KEY or
	// UNIQUE constraint. Such an index is not an independent object (it
	// cannot be dropped on its own), so re-emitting it would duplicate
	// the constraint it belongs to.
	constraintIndexNames := map[string]map[string]bool{}
	markConstraintIndex := func(table, name string) {
		if constraintIndexNames[table] == nil {
			constraintIndexNames[table] = map[string]bool{}
		}
		constraintIndexNames[table][name] = true
	}
	fkByTable := map[string][]fkRecord{} // table → FK records
	ckByTable := map[string][]keystonev1alpha1.DesiredCheckConstraint{}
	uqByTable := map[string][]keystonev1alpha1.DesiredUniqueConstraint{}
	for _, c := range snap.Constraints {
		switch c.Type {
		case "PRIMARY KEY":
			pkByTable[c.Table] = parseConstraintCols(c.Definition)
			// Recorded verbatim rather than only when it differs from
			// PostgreSQL's `<table>_pkey` default: reproducing the default
			// would mean re-deriving it, and PostgreSQL truncates it at 63
			// bytes, so the "is this the default?" test is a guess where
			// the catalog already holds the answer.
			pkNameByTable[c.Table] = c.Name
			markConstraintIndex(c.Table, c.Name)
		case "UNIQUE":
			// Carried as a constraint rather than folded into Indexes:
			// PostgreSQL only accepts a PRIMARY KEY or UNIQUE constraint
			// as a foreign-key target, so demoting one to a unique index
			// round-trips the schema into a shape where existing FKs
			// referencing these columns can no longer be created.
			cols := parseConstraintCols(c.Definition)
			if len(cols) == 0 {
				continue
			}
			uqByTable[c.Table] = append(uqByTable[c.Table],
				keystonev1alpha1.DesiredUniqueConstraint{
					Name:             c.Name,
					Columns:          cols,
					NullsNotDistinct: hasNullsNotDistinct(c.Definition),
				})
			markConstraintIndex(c.Table, c.Name)
		case "FOREIGN KEY":
			fk := parseFKConstraint(c.Name, c.Definition)
			if fk.name != "" {
				fkByTable[c.Table] = append(fkByTable[c.Table], fk)
			}
		case "CHECK":
			// Without this the desired spec carries no CHECK constraints at
			// all, so the differ sees every existing one as removed and
			// authors a bare DROP CONSTRAINT with no matching ADD — silently
			// deleting data-integrity rules — while never creating the ones
			// the desired schema declares.
			if expr := parseCheckExpression(c.Definition); expr != "" {
				ckByTable[c.Table] = append(ckByTable[c.Table],
					keystonev1alpha1.DesiredCheckConstraint{Name: c.Name, Definition: expr})
			}
		}
	}

	// Index indexes by table.
	idxByTable := map[string][]drift.ObjectDDL{}
	for _, idx := range snap.Indexes {
		idxByTable[idx.Table] = append(idxByTable[idx.Table], idx)
	}

	// Tables (BASE TABLE only — views handled separately).
	for _, t := range snap.Tables {
		if t.Kind == "VIEW" {
			continue
		}
		dt := keystonev1alpha1.DesiredTable{
			Name:              t.Name,
			Columns:           make([]keystonev1alpha1.DesiredColumn, 0, len(t.Columns)),
			CheckConstraints:  ckByTable[t.Name],
			UniqueConstraints: uqByTable[t.Name],
			PrimaryKeyName:    pkNameByTable[t.Name],
		}

		// Columns.
		pkCols := map[string]bool{}
		for _, col := range pkByTable[t.Name] {
			pkCols[col] = true
		}
		for _, c := range t.Columns {
			dc := keystonev1alpha1.DesiredColumn{
				Name:      c.Name,
				Type:      keystonev1alpha1.ColumnType(drift.ResolveColumnTypeShape(c)),
				Identity:  identityKeyword(c.Identity),
				Generated: c.Generated,
				Nullable:  c.Nullable,
				Default:   c.Default,
			}
			if pkCols[c.Name] && len(pkByTable[t.Name]) == 1 {
				dc.PrimaryKey = true
			}
			dt.Columns = append(dt.Columns, dc)
		}

		// Composite PK.
		if pk := pkByTable[t.Name]; len(pk) > 1 {
			dt.PrimaryKey = pk
		}

		// Indexes, minus the index PostgreSQL creates to back the primary
		// key. That index is not an independent object — it cannot be
		// dropped separately, and re-emitting it produces a CREATE UNIQUE
		// INDEX alongside (or instead of) the PRIMARY KEY it belongs to.
		//
		// Matched by name, which is exact: PostgreSQL always names a
		// constraint's backing index after the constraint, including when
		// ADD CONSTRAINT ... USING INDEX renames an existing one. The
		// previous `_pkey` suffix test was a guess at PostgreSQL's default
		// constraint name, so it missed every explicitly-named PK — which
		// is what ORMs generate (EF Core emits `PK_Todos`) — and would
		// have wrongly dropped a hand-written index called `*_pkey`.
		for _, idx := range idxByTable[t.Name] {
			if constraintIndexNames[t.Name][idx.Name] {
				continue
			}
			di := parseIndexDDL(idx)
			if di.Name != "" {
				dt.Indexes = append(dt.Indexes, di)
			}
		}

		// Foreign keys.
		for _, fk := range fkByTable[t.Name] {
			dt.ForeignKeys = append(dt.ForeignKeys, keystonev1alpha1.DesiredForeignKey{
				Name:              fk.name,
				Columns:           fk.columns,
				ReferencesTable:   fk.refTable,
				ReferencesColumns: fk.refColumns,
				OnDelete:          fk.onDelete,
			})
		}

		spec.Tables = append(spec.Tables, dt)
	}

	// Enums.
	for _, e := range snap.Enums {
		spec.Enums = append(spec.Enums, keystonev1alpha1.DesiredEnum{
			Name:   e.Name,
			Values: e.Labels,
		})
	}

	// Sequences.
	for _, s := range snap.Sequences {
		spec.Sequences = append(spec.Sequences, keystonev1alpha1.DesiredSequence{
			Name:        s.Name,
			DataType:    s.DataType,
			IncrementBy: s.IncrementBy,
			MinValue:    s.MinValue,
			MaxValue:    s.MaxValue,
			StartWith:   s.StartValue,
		})
	}

	// Views.
	for _, t := range snap.Tables {
		if t.Kind != "VIEW" {
			continue
		}
		spec.Views = append(spec.Views, keystonev1alpha1.DesiredView{
			Name:    t.Name,
			Query:   strings.TrimSpace(t.ViewDefinition),
			Replace: true,
		})
	}

	// Functions.
	for _, f := range snap.Functions {
		spec.Functions = append(spec.Functions, keystonev1alpha1.DesiredFunction{
			Name:     f.Name,
			Args:     f.Args,
			Returns:  f.Returns,
			Language: f.Language,
			Body:     extractFunctionBody(f.Definition),
			Replace:  true,
		})
	}

	// RLS flags per table — copy the relrowsecurity / relforcerowsecurity
	// bits back onto each DesiredTable. The Differ reads
	// spec.tables[].enableRLS and .forceRLS when emitting
	// ALTER TABLE … ENABLE / FORCE ROW LEVEL SECURITY.
	//
	// forceRLS is emitted explicitly — including as `false` — whenever RLS
	// is enabled, rather than being left unset to pick up its default. A
	// SchemaDefinition produced by inspecting a live database is a record of
	// what that database actually is, and "enabled but not forced" is a
	// state a database can genuinely be in. Omitting the field there would
	// round-trip that table back as forced, quietly describing protection
	// the inspected database does not have.
	//
	// A nil RLSForced means the snapshot predates the field, so its FORCE
	// state was never recorded. There the field is left unset, which means
	// forced — the safe reading, and the one that matches how every
	// SchemaDefinition written before the field behaved.
	if len(snap.Tables) > 0 {
		type rlsBits struct {
			enabled bool
			forced  *bool
		}
		rls := make(map[string]rlsBits, len(snap.Tables))
		for _, t := range snap.Tables {
			rls[t.Name] = rlsBits{enabled: t.RLSEnabled, forced: t.RLSForced}
		}
		for i := range spec.Tables {
			b, ok := rls[spec.Tables[i].Name]
			if !ok || !b.enabled {
				continue
			}
			spec.Tables[i].EnableRLS = true
			if b.forced != nil {
				forced := *b.forced
				spec.Tables[i].ForceRLS = &forced
			}
		}
	}

	// Policies — one DesiredPolicy per pg_policies row.
	for _, p := range snap.Policies {
		spec.Policies = append(spec.Policies, keystonev1alpha1.DesiredPolicy{
			Name:       p.Name,
			Table:      p.Table,
			Command:    p.Command,
			Permissive: p.Permissive,
			Roles:      p.Roles,
			Using:      p.Using,
			WithCheck:  p.WithCheck,
		})
	}

	// Triggers — skip internal FK-enforcement triggers (already filtered
	// by the inspector). Only project user triggers into the SD.
	for _, tr := range snap.Triggers {
		spec.Triggers = append(spec.Triggers, keystonev1alpha1.DesiredTrigger{
			Name:       tr.Name,
			Table:      tr.Table,
			Timing:     tr.Timing,
			Events:     tr.Events,
			ForEachRow: tr.ForEachRow,
			Function:   tr.Function,
			When:       tr.When,
		})
	}

	// Materialized views — the Differ creates/refreshes these after
	// base tables are in place, so spec ordering does not matter here.
	for _, mv := range snap.MaterializedViews {
		spec.MaterializedViews = append(spec.MaterializedViews, keystonev1alpha1.DesiredMaterializedView{
			Name:     mv.Name,
			Query:    strings.TrimSpace(mv.Definition),
			WithData: true,
		})
	}

	return spec
}

// fkRecord is a parsed FK constraint.
type fkRecord struct {
	name       string
	columns    []string
	refTable   string
	refColumns []string
	onDelete   string
}

// parseConstraintCols extracts column names from a constraint definition.
func parseConstraintCols(def string) []string {
	open := strings.IndexByte(def, '(')
	closeIdx := strings.LastIndexByte(def, ')')
	if open < 0 || closeIdx < 0 || closeIdx <= open {
		return nil
	}
	return splitQuotedIdentList(def[open+1 : closeIdx])
}

// unquoteIdent removes the surrounding double quotes PostgreSQL adds to
// any identifier that is not a bare lowercase word, collapsing the
// doubled `""` escape back to a single quote character.
//
// Carrying the quotes through would be silently wrong twice over: the
// name no longer matches the column or table it names, and re-quoting it
// on emit produces `"""Tenants"""`.
func unquoteIdent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	return strings.ReplaceAll(s[1:len(s)-1], `""`, `"`)
}

// hasNullsNotDistinct reports whether a UNIQUE constraint definition
// carries the NULLS NOT DISTINCT modifier (PostgreSQL 15+).
//
// pg_get_constraintdef renders it between the keyword and the column
// list — `UNIQUE NULLS NOT DISTINCT (c)` — so it must be read off the
// prefix before parseConstraintCols takes the parenthesised part. The
// default (NULLS DISTINCT) lets a nullable unique column hold unlimited
// NULL rows, so losing this flag silently widens what the table accepts.
func hasNullsNotDistinct(def string) bool {
	open := strings.IndexByte(def, '(')
	head := def
	if open >= 0 {
		head = def[:open]
	}
	return strings.Contains(strings.ToUpper(head), "NULLS NOT DISTINCT")
}

// splitQuotedIdentList splits a PostgreSQL identifier list on commas and
// unquotes each element.
//
// pg_get_constraintdef quotes any identifier that is not a bare lowercase
// word, so a table created by an ORM comes back as `PRIMARY KEY ("Id")`.
// Splitting naively and keeping the quotes yields `"Id"`, which then
// matches no column name — the primary key silently vanishes from the
// desired state, and the schema round-trips without one. A missing PK is
// not cosmetic: foreign keys can only reference a PRIMARY KEY or UNIQUE
// *constraint*, logical replication needs a replica identity, and the
// pgroll operations assume one.
//
// Splitting is quote-aware because a quoted identifier may legally
// contain a comma — `PRIMARY KEY ("a,b", c)` is two columns, not three.
// Inside quotes, `""` is an escaped double quote.
func splitQuotedIdentList(inner string) []string {
	var (
		cols []string
		cur  strings.Builder
		in   bool // inside a quoted identifier
	)
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			cols = append(cols, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case c == '"':
			if in && i+1 < len(inner) && inner[i+1] == '"' {
				cur.WriteByte('"') // escaped quote inside the identifier
				i++
				continue
			}
			in = !in
		case c == ',' && !in:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return cols
}

// parseFKConstraint extracts FK details from pg_get_constraintdef output.
// Input: "FOREIGN KEY (col) REFERENCES target(tcol) ON DELETE CASCADE"
func parseFKConstraint(name, def string) fkRecord {
	rec := fkRecord{name: name, onDelete: "NO ACTION"}
	upper := strings.ToUpper(def)

	// Parse FK columns.
	fkIdx := strings.Index(upper, "FOREIGN KEY")
	if fkIdx < 0 {
		return fkRecord{}
	}
	rest := def[fkIdx+len("FOREIGN KEY"):]
	open := strings.IndexByte(rest, '(')
	closeIdx := strings.IndexByte(rest, ')')
	if open < 0 || closeIdx < 0 {
		return fkRecord{}
	}
	rec.columns = splitQuotedIdentList(rest[open+1 : closeIdx])

	// Parse REFERENCES.
	refIdx := strings.Index(upper, "REFERENCES ")
	if refIdx < 0 {
		return fkRecord{}
	}
	refRest := def[refIdx+len("REFERENCES "):]
	refParen := strings.IndexByte(refRest, '(')
	if refParen < 0 {
		return fkRecord{}
	}
	rec.refTable = strings.TrimSpace(refRest[:refParen])
	// Strip the schema prefix, then unquote — in that order, because the
	// separating dot sits outside the quotes (`app."Tenants"`).
	if dot := strings.LastIndexByte(rec.refTable, '.'); dot >= 0 {
		rec.refTable = rec.refTable[dot+1:]
	}
	rec.refTable = unquoteIdent(rec.refTable)
	refClose := strings.IndexByte(refRest[refParen:], ')')
	if refClose >= 0 {
		rec.refColumns = splitQuotedIdentList(refRest[refParen+1 : refParen+refClose])
	}

	// Parse ON DELETE.
	if idx := strings.Index(upper, "ON DELETE "); idx >= 0 {
		action := strings.TrimSpace(def[idx+len("ON DELETE "):])
		// Take up to next keyword or end.
		for _, kw := range []string{" ON ", " DEFERRABLE", " NOT "} {
			if ki := strings.Index(strings.ToUpper(action), kw); ki >= 0 {
				action = action[:ki]
			}
		}
		action = strings.TrimSpace(action)
		if action != "" {
			rec.onDelete = strings.ToUpper(action)
		}
	}
	return rec
}

// parseIndexDDL extracts a DesiredIndex from a pg_indexes DDL string.
//
// Handles every shape the DesiredIndex CRD models:
//   - simple columns           ->  Columns []string
//   - per-column DESC/NULLS    ->  ColumnRefs []DesiredIndexColumn
//   - per-column opclass       ->  ColumnRefs[i].OpClass
//   - expression body          ->  Expression
//   - INCLUDE / covering       ->  Include
//   - partial WHERE predicate  ->  Where
//
// pg_indexes.indexdef format:
//
//	CREATE [UNIQUE] INDEX <name> ON <schema>.<table>
//	  USING <method>
//	  ( col1 [opclass] [ASC|DESC] [NULLS FIRST|LAST], col2 ... | (expression) )
//	  [INCLUDE (col, col, ...)]
//	  [WHERE predicate]
func parseIndexDDL(idx drift.ObjectDDL) keystonev1alpha1.DesiredIndex {
	di := keystonev1alpha1.DesiredIndex{Name: idx.Name}
	def := idx.Definition
	upper := strings.ToUpper(def)

	di.Unique = strings.Contains(upper, "UNIQUE INDEX")

	// Extract method (USING btree/hash/gin/gist/brin/spgist).
	if usingIdx := strings.Index(upper, " USING "); usingIdx >= 0 {
		rest := def[usingIdx+len(" USING "):]
		parenIdx := strings.IndexByte(rest, ' ')
		if pIdx := strings.IndexByte(rest, '('); pIdx >= 0 && (parenIdx < 0 || pIdx < parenIdx) {
			parenIdx = pIdx
		}
		if parenIdx > 0 {
			di.Method = strings.TrimSpace(rest[:parenIdx])
		}
	}
	if di.Method == "" {
		di.Method = "btree"
	}

	// Extract WHERE clause first so the column-list parser doesn't
	// see WHERE-side material.
	bodyEnd := len(def)
	if whereIdx := strings.Index(upper, " WHERE "); whereIdx >= 0 {
		di.Where = strings.TrimSpace(def[whereIdx+len(" WHERE "):])
		bodyEnd = whereIdx
	}

	// Extract NULLS NOT DISTINCT (PG 15+, only valid with UNIQUE).
	// pg_get_indexdef emits it AFTER the column-list parens (and any
	// INCLUDE clause) and BEFORE WHERE. Only meaningful for UNIQUE
	// indexes — but the keyword itself is not gated on UNIQUE in pg
	// catalog so we read it unconditionally and let the renderer
	// decide whether to emit it.
	body0 := def[:bodyEnd]
	if nndIdx := strings.Index(strings.ToUpper(body0), " NULLS NOT DISTINCT"); nndIdx >= 0 {
		di.NullsNotDistinct = true
		bodyEnd = nndIdx
	}

	// Extract INCLUDE clause if present (between main parens and WHERE).
	body := def[:bodyEnd]
	if incIdx := strings.Index(strings.ToUpper(body), " INCLUDE "); incIdx >= 0 {
		incStr := body[incIdx+len(" INCLUDE "):]
		if open, closeIdx := matchedParens(incStr); open >= 0 && closeIdx > open {
			incCols := splitTopLevelCommas(incStr[open+1 : closeIdx])
			for _, c := range incCols {
				if c = strings.TrimSpace(c); c != "" {
					di.Include = append(di.Include, c)
				}
			}
		}
		body = body[:incIdx]
	}

	// Extract main column list (between method's parens).
	usingIdx := strings.Index(strings.ToUpper(body), " USING ")
	if usingIdx < 0 {
		return keystonev1alpha1.DesiredIndex{}
	}
	rest := body[usingIdx:]
	open, closeIdx := matchedParens(rest)
	if open < 0 || closeIdx <= open {
		return keystonev1alpha1.DesiredIndex{}
	}
	colStr := rest[open+1 : closeIdx]

	// Detect expression-index shape: body is `(<expression>)` — i.e.
	// the inner content itself starts with `(` and is balanced. PG
	// emits expression indexes as `... USING btree ((lower(col)))`.
	trimmed := strings.TrimSpace(colStr)
	if strings.HasPrefix(trimmed, "(") {
		eo, ec := matchedParens(trimmed)
		if eo == 0 && ec == len(trimmed)-1 {
			di.Expression = trimmed[1:ec]
			return di
		}
	}

	// Multi-column list. For each comma-separated entry, parse:
	//   <name> [opclass] [ASC|DESC] [NULLS FIRST|LAST]
	// or per-column expression:
	//   <expression-body> [opclass] [ASC|DESC] [NULLS FIRST|LAST]
	//
	// If any entry has modifiers OR is a per-column expression, emit
	// ColumnRefs for the whole list (so the round-trip is faithful).
	// Otherwise stick with simple Columns for backwards-compat-friendly
	// output.
	parts := splitTopLevelCommas(colStr)
	hasModifiers := false
	parsed := make([]keystonev1alpha1.DesiredIndexColumn, 0, len(parts))
	simple := make([]string, 0, len(parts))
	for _, p := range parts {
		entry := strings.TrimSpace(p)
		ref, isExpr := parseColumnRefEntry(entry)
		if ref.Name == "" && ref.Expression == "" {
			continue
		}
		if isExpr || ref.Direction != "" || ref.Nulls != "" || ref.OpClass != "" {
			hasModifiers = true
		}
		parsed = append(parsed, ref)
		if ref.Name != "" {
			simple = append(simple, ref.Name)
		}
	}
	if hasModifiers {
		di.ColumnRefs = parsed
	} else {
		di.Columns = simple
	}

	if len(di.Columns) == 0 && len(di.ColumnRefs) == 0 {
		return keystonev1alpha1.DesiredIndex{}
	}
	return di
}

// parseColumnRefEntry parses one column-list entry into a
// DesiredIndexColumn. Returns the populated entry and isExpr=true if
// the body is a per-column SQL expression rather than a column name.
//
// Valid shapes:
//
//	col_name [opclass] [ASC|DESC] [NULLS FIRST|LAST]
//	function_call(args) [opclass] [ASC|DESC] [NULLS FIRST|LAST]
//	(expression body) [opclass] [ASC|DESC] [NULLS FIRST|LAST]
//	col_name::cast_target [...]   — type-cast column ref counts as expression
func parseColumnRefEntry(s string) (keystonev1alpha1.DesiredIndexColumn, bool) {
	if s == "" {
		return keystonev1alpha1.DesiredIndexColumn{}, false
	}

	// Detect expression-form bodies. Two cases PG emits:
	//   1. Wrapped:  `(lower(col))`  — outer parens balance the body
	//   2. Bare:     `coalesce(col, '')` or `(col)::text`
	body, modifiers := splitBodyAndModifiers(s)
	if body == "" {
		return keystonev1alpha1.DesiredIndexColumn{}, false
	}

	mods := parseColumnModifiers(modifiers)

	if isExpressionBody(body) {
		// Strip wrapping parens if the entire body is one balanced
		// pair (PG emits `(lower(col))` for some shapes; we want the
		// inner body so the renderer's own paren-wrapping doesn't
		// double up).
		if strings.HasPrefix(body, "(") {
			eo, ec := matchedParens(body)
			if eo == 0 && ec == len(body)-1 {
				body = body[1:ec]
			}
		}
		mods.Expression = body
		return mods, true
	}

	// Plain column ref. Strip surrounding double-quotes (PG emits
	// `"My Col"` for non-lowercase identifiers; the CRD pattern
	// requires lowercase, so quoted names that don't match the
	// pattern would be rejected at apply time — operator can fix
	// in the SD source).
	mods.Name = strings.Trim(body, `"`)
	return mods, false
}

// splitBodyAndModifiers cuts a column-list entry into its body
// (column name or expression) and the modifier suffix tokens
// (opclass / ASC|DESC / NULLS FIRST|LAST).
//
// The body may contain spaces (within balanced parens), so we walk
// the string respecting paren depth and detect the modifier-suffix
// boundary as the first whitespace at depth 0 AFTER the body's
// opening structure.
func splitBodyAndModifiers(s string) (body string, modifiers string) {
	depth := 0
	bodyEnd := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ' ', '\t':
			if depth == 0 && i > 0 {
				bodyEnd = i
			}
		}
		if bodyEnd >= 0 {
			break
		}
	}
	if bodyEnd < 0 {
		return s, ""
	}
	return s[:bodyEnd], strings.TrimSpace(s[bodyEnd:])
}

// parseColumnModifiers extracts opclass / direction / nulls from the
// modifier-suffix tokens.
func parseColumnModifiers(s string) keystonev1alpha1.DesiredIndexColumn {
	if s == "" {
		return keystonev1alpha1.DesiredIndexColumn{}
	}
	tokens := strings.Fields(s)
	var mods keystonev1alpha1.DesiredIndexColumn
	for i := 0; i < len(tokens); i++ {
		t := strings.ToUpper(tokens[i])
		switch t {
		case "ASC":
			mods.Direction = "asc"
		case "DESC":
			mods.Direction = "desc"
		case "NULLS":
			if i+1 < len(tokens) {
				switch strings.ToUpper(tokens[i+1]) {
				case "FIRST":
					mods.Nulls = "first"
				case "LAST":
					mods.Nulls = "last"
				}
				i++
			}
		default:
			candidate := strings.Trim(tokens[i], `"`)
			if mods.OpClass == "" && candidate != "" {
				mods.OpClass = candidate
			}
		}
	}
	return mods
}

// isExpressionBody reports whether the column-entry body is a SQL
// expression rather than a plain column reference. Indicators:
//   - contains `(` (function call or wrapped expression)
//   - contains `::` (type cast literal in body)
func isExpressionBody(s string) bool {
	if strings.Contains(s, "::") {
		return true
	}
	return strings.IndexByte(s, '(') >= 0
}

// matchedParens finds the first '(' in s and the matching ')' that
// closes it, accounting for nested parens. Returns -1, -1 if none.
func matchedParens(s string) (int, int) {
	open := strings.IndexByte(s, '(')
	if open < 0 {
		return -1, -1
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return open, i
			}
		}
	}
	return open, -1
}

// splitTopLevelCommas splits a string on commas that are NOT inside
// parentheses. Used to split index column lists where individual
// entries can be expressions like `coalesce(col, 0)` containing
// internal commas.
func splitTopLevelCommas(s string) []string {
	out := []string{}
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// extractFunctionBody pulls the body from a pg_get_functiondef output.
// It looks for $$ or $fn$ delimiters and extracts between them.
func extractFunctionBody(def string) string {
	for _, delim := range []string{"$$", "$fn$", "$function$", "$body$"} {
		first := strings.Index(def, delim)
		if first < 0 {
			continue
		}
		second := strings.Index(def[first+len(delim):], delim)
		if second >= 0 {
			return def[first+len(delim) : first+len(delim)+second]
		}
	}
	return def // fallback: return the full definition
}

// identityKeyword maps pg_attribute.attidentity onto the SchemaDefinition
// spelling. Kept here rather than in drift so the SDK's snapshot type stays
// free of Kubernetes API vocabulary.
func identityKeyword(attidentity string) string {
	switch attidentity {
	case "a":
		return "ALWAYS"
	case "d":
		return "BY DEFAULT"
	default:
		return ""
	}
}

// parseCheckExpression pulls the predicate body out of a
// pg_get_constraintdef result so it can be re-emitted inside CHECK (...).
//
// pg_get_constraintdef returns "CHECK ((quantity > 0))" — the keyword, then
// the expression already wrapped in its own parentheses, optionally followed
// by NOT VALID. One layer of parentheses is removed so the renderer's own
// CHECK (%s) reproduces the original text rather than nesting further.
//
// Returns "" when the input is not a CHECK definition, so a caller cannot
// accidentally emit a malformed constraint from an unexpected shape.
func parseCheckExpression(def string) string {
	s := strings.TrimSpace(def)

	// Trailing NOT VALID is a property of the constraint, not the predicate.
	if idx := strings.LastIndex(strings.ToUpper(s), " NOT VALID"); idx >= 0 && idx == len(s)-len(" NOT VALID") {
		s = strings.TrimSpace(s[:idx])
	}

	const kw = "CHECK"
	if len(s) < len(kw) || !strings.EqualFold(s[:len(kw)], kw) {
		return ""
	}
	s = strings.TrimSpace(s[len(kw):])

	// Strip exactly one balanced outer paren pair.
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return ""
	}
	depth := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			// The opening paren closes before the end: the outer pair does not
			// wrap the whole expression, so removing it would change meaning.
			if depth == 0 && i != len(s)-1 {
				return s
			}
		}
	}
	return strings.TrimSpace(s[1 : len(s)-1])
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package declarative implements Keystone's schema differ.
//
// The differ takes two inputs:
//
//  1. Observed state — a drift.Snapshot produced by the inspector
//     reading information_schema on the live database
//  2. Desired state — a SchemaDefinition.spec describing the target
//
// And produces:
//
//   - SQL statements (when applyStrategy=versioned) that transform
//     observed → desired
//   - Reverse SQL statements for each forward operation (for rollback)
//   - Warnings (non-fatal advisories: nullability changes, etc.)
//   - Refusal (hard error) when the diff would require destructive ops
//     and SchemaDefinition.spec.allowDestructive=false
//
// The differ does NOT issue DDL — it returns statements that the
// MigrationBundle reconciler packages into a ConfigMap and applies.
//
// Phase 9.2 additions over the original Phase 10.2 differ:
//   - Enum, Sequence, View, Function diffing
//   - Topological sort for CREATE TABLE (FK dependency ordering)
//   - CREATE INDEX CONCURRENTLY support
//   - NOT NULL + DEFAULT backfill (SET DEFAULT → UPDATE → SET NOT NULL)
//   - Reverse SQL generation for each forward operation
//   - Full snapshot index/constraint threading through diffTable
//   - FK constraint diff (add NOT VALID + VALIDATE, drop)
package declarative

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	pg "github.com/dogukanturhal/keystone-sdk/go/sqlquote"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Plan is the differ's output. Statements are ordered safe-first
// (creates before alters; adds before drops) so a crash mid-apply
// leaves the schema in a coherent state.
type Plan struct {
	// Statements is the ordered list of SQL to apply.
	Statements []string

	// ReverseStatements is the corresponding rollback SQL for each
	// forward statement. Index-aligned with Statements: ReverseStatements[i]
	// undoes Statements[i]. Empty string means the operation is not
	// reversible (e.g., DROP COLUMN data loss).
	ReverseStatements []string

	// Warnings is non-fatal advisories.
	Warnings []string

	// DestructiveOps counts statements that cannot be taken back by
	// re-running the differ: DROP TABLE / DROP COLUMN / DROP INDEX /
	// DROP CONSTRAINT / DROP TYPE / DROP SEQUENCE / DROP VIEW /
	// DROP FUNCTION, plus NO FORCE ROW LEVEL SECURITY. The last one
	// destroys no data but exempts the table owner from every policy on
	// the table, which on a multi-tenant schema is a wider blast radius
	// than most DROPs — it belongs behind the same approval gate.
	DestructiveOps int
}

// Empty reports whether the plan contains no statements.
func (p *Plan) Empty() bool { return len(p.Statements) == 0 }

// emit adds a forward statement and its reverse to the plan.
func (p *Plan) emit(forward, reverse string) {
	p.Statements = append(p.Statements, forward)
	p.ReverseStatements = append(p.ReverseStatements, reverse)
}

// emitDestructive adds a destructive statement and increments the counter.
func (p *Plan) emitDestructive(forward, reverse string) {
	p.emit(forward, reverse)
	p.DestructiveOps++
}

// ErrDestructiveRefused is returned when the diff contains destructive
// ops but spec.allowDestructive=false. The Plan is attached so the
// caller can surface the would-be-applied statements on status without
// re-running the differ; PendingOperations on the parent CR mirrors
// len(Plan.Statements).
type ErrDestructiveRefused struct {
	Count int
	Plan  *Plan
}

func (e *ErrDestructiveRefused) Error() string {
	return fmt.Sprintf("%d destructive operation(s) refused; "+
		"set spec.allowDestructive=true to permit", e.Count)
}

// Diff computes the SQL transformation from observed to desired state.
// Statements are emitted in canonical safe-first order:
//  1. CREATE TYPE (enums)
//  2. CREATE SEQUENCE
//  3. CREATE TABLE (topologically sorted by FK dependencies)
//  4. ALTER TABLE (columns, constraints)
//  5. CREATE INDEX CONCURRENTLY
//  6. CREATE VIEW
//  7. CREATE FUNCTION
//  8. DROP (in reverse dependency order)
func Diff(observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) (*Plan, error) {
	if observed == nil {
		return nil, fmt.Errorf("observed snapshot is nil")
	}
	if desired == nil {
		return nil, fmt.Errorf("desired spec is nil")
	}
	plan := &Plan{}
	schema := observed.Schema

	// Build indexes for observed state.
	obsTables := observedTables(observed)
	obsIdxByTable := observedIndexesByTable(observed)
	obsCstByTable := observedConstraintsByTable(observed)

	desTables := desiredTables(desired)

	// --- Phase 0a: Extensions ---
	// Before everything, including enums: an extension supplies types that
	// columns and even other types are declared with.
	diffExtensions(plan, observed, desired)

	// --- Phase 0b: Enums ---
	diffEnums(plan, schema, observed, desired)

	// --- Phase 1: Sequences ---
	diffSequences(plan, schema, observed, desired)

	// --- Phase 2: Tables (topologically sorted for CREATE, then ALTER) ---
	createOrder, hasCycle := topoSortTables(desired.Tables)
	if hasCycle {
		plan.Warnings = append(plan.Warnings,
			"circular foreign key dependencies detected; tables with cycles "+
				"are appended alphabetically — consider using deferred constraints")
	}
	for _, name := range createOrder {
		dt := desTables[name]
		if _, existsInObs := obsTables[name]; !existsInObs {
			plan.emit(
				renderCreateTable(schema, dt),
				// IF EXISTS on reverse: re-applying a bundle that was
				// partially applied (or applying after a manual
				// cleanup) must not fail on rollback if the table is
				// already gone. The diff is convergence-toward-desired,
				// not strict transaction-safety against drift.
				fmt.Sprintf("DROP TABLE IF EXISTS %s.%s",
					pg.QuoteIdentifier(schema), pg.QuoteIdentifier(name)),
			)
		}
	}

	// Build observed-table-name set for FK target reachability.
	// Used by diffTableFull's FK target guard to skip orphan FK
	// declarations (target table missing from both observed and
	// desired-being-created).
	obsTableNames := make(map[string]struct{}, len(obsTables))
	for n := range obsTables {
		obsTableNames[n] = struct{}{}
	}

	// ALTER existing tables: columns, indexes, FKs.
	for _, name := range createOrder {
		dt := desTables[name]
		ot, existsInObs := obsTables[name]
		if !existsInObs {
			continue
		}
		obsIdx := obsIdxByTable[name]
		obsCst := obsCstByTable[name]
		diffTableFull(plan, schema, ot, dt, obsIdx, obsCst, obsTableNames)
	}

	// New tables: emit their secondary objects (indexes, foreign keys,
	// CHECK constraints). renderCreateTable only emitted columns + the
	// primary key in the CREATE wave above; everything else is created
	// here, after every CREATE TABLE is queued so FK targets resolve via
	// tableReachable.
	for _, name := range createOrder {
		if _, existsInObs := obsTables[name]; existsInObs {
			continue
		}
		diffTableObjects(plan, schema, desTables[name], nil, nil, obsTableNames)
	}

	// Tables in observed but not desired → DROP TABLE (reverse dependency order).
	for _, o := range sortedObservedNames(obsTables) {
		if _, ok := desTables[o]; ok {
			continue
		}
		plan.emitDestructive(
			// IF EXISTS: re-applying after partial apply or out-of-band
			// drop must not throw `relation X does not exist`. Diff
			// already says "this table should not exist" — getting
			// there is the goal regardless of starting state.
			fmt.Sprintf("DROP TABLE IF EXISTS %s.%s",
				pg.QuoteIdentifier(schema), pg.QuoteIdentifier(o)),
			"", // not reversible — data loss
		)
	}

	// --- Phase 2b: Enable RLS on tables that need it ---
	diffRLS(plan, schema, observed, desired)

	// --- Phase 3: Views ---
	diffViews(plan, schema, observed, desired)

	// --- Phase 3b: Materialized Views ---
	diffMaterializedViews(plan, schema, observed, desired)

	// --- Phase 4: Functions ---
	diffFunctions(plan, schema, observed, desired)

	// --- Phase 5: Triggers ---
	diffTriggers(plan, schema, observed, desired)

	// --- Phase 6: RLS Policies ---
	diffPolicies(plan, schema, observed, desired)

	if !desired.AllowDestructive && plan.DestructiveOps > 0 {
		return plan, &ErrDestructiveRefused{Count: plan.DestructiveOps, Plan: plan}
	}
	return plan, nil
}

// --- Enum diffing ---

// diffExtensions emits CREATE EXTENSION for anything the desired spec
// declares that is not already installed.
//
// Creation only. DROP EXTENSION is deliberately never authored: extensions are
// database-scoped and routinely shared by other schemas in the same database,
// so dropping one because a single schema stopped referencing it would break
// tenants the differ cannot see.
func diffExtensions(plan *Plan, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	installed := make(map[string]bool, len(observed.Extensions))
	for _, x := range observed.Extensions {
		installed[x.Name] = true
	}

	for _, x := range desired.Extensions {
		if installed[x.Name] {
			continue
		}

		stmt := fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %s", pg.QuoteIdentifier(x.Name))
		if x.Schema != "" {
			stmt += fmt.Sprintf(" SCHEMA %s", pg.QuoteIdentifier(x.Schema))
		}

		plan.Statements = append(plan.Statements, stmt)
	}
}

func diffEnums(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Build observed enum index for comparison.
	obsEnums := make(map[string]map[string]bool, len(observed.Enums))
	for _, e := range observed.Enums {
		labels := make(map[string]bool, len(e.Labels))
		for _, l := range e.Labels {
			labels[l] = true
		}
		obsEnums[e.Name] = labels
	}

	for _, e := range desired.Enums {
		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(e.Name))

		existingLabels := obsEnums[e.Name]

		if existingLabels == nil {
			// Enum doesn't exist yet — CREATE TYPE.
			//
			// PG does NOT support `CREATE TYPE ... IF NOT EXISTS` (any
			// version through PG 17). The idempotent pattern is a
			// `DO $$ BEGIN ... EXCEPTION duplicate_object` block —
			// catches the SQLSTATE 42710 raised when a parallel apply
			// or out-of-band CREATE TYPE landed the type between our
			// observed-snapshot and apply.
			//
			// Previously the differ emitted the bare
			// `CREATE TYPE %s AS ENUM (...)` and produced 3× live
			// failures on 2026-05-18 (type tenant_type already exists,
			// SQLSTATE 42710) when the SchemaDefinition was applied a
			// second time after a prior partial apply left the type
			// behind.
			valList := make([]string, 0, len(e.Values))
			for _, v := range e.Values {
				valList = append(valList, fmt.Sprintf("'%s'", escapeEnumValue(v)))
			}
			createSQL := fmt.Sprintf(
				"DO $$ BEGIN CREATE TYPE %s AS ENUM (%s); EXCEPTION WHEN duplicate_object THEN NULL; END $$",
				qualified, strings.Join(valList, ", "))
			plan.emit(
				createSQL,
				// IF EXISTS on reverse — symmetric with DROP TABLE /
				// DROP SEQUENCE / DROP VIEW / DROP FUNCTION guards
				// elsewhere in this differ.
				fmt.Sprintf("DROP TYPE IF EXISTS %s", qualified))
		} else {
			// Enum exists — only add new values.
			for _, v := range e.Values {
				if existingLabels[v] {
					continue
				}
				plan.emit(
					fmt.Sprintf("ALTER TYPE %s ADD VALUE IF NOT EXISTS '%s'",
						qualified, escapeEnumValue(v)),
					"", // PG cannot remove enum values
				)
			}
			// Warn about values in observed but not in desired (PG can't remove).
			for label := range existingLabels {
				found := false
				for _, v := range e.Values {
					if v == label {
						found = true
						break
					}
				}
				if !found {
					plan.Warnings = append(plan.Warnings, fmt.Sprintf(
						"enum %s has label %q in database but not in desired spec — "+
							"PostgreSQL does not support removing enum values",
						e.Name, label))
				}
			}
		}
	}
}

func escapeEnumValue(v string) string {
	return strings.ReplaceAll(v, "'", "''")
}

// --- Sequence diffing ---

func diffSequences(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Index observed sequences by name.
	obsSeqs := make(map[string]drift.SeqShape, len(observed.Sequences))
	for _, s := range observed.Sequences {
		obsSeqs[s.Name] = s
	}

	for _, s := range desired.Sequences {
		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(s.Name))

		dt := s.DataType
		if dt == "" {
			dt = "bigint"
		}
		inc := s.IncrementBy
		if inc == 0 {
			inc = 1
		}

		// Skip CREATE emit when an equivalent sequence already exists.
		// Without this, every reconcile re-emits CREATE SEQUENCE IF NOT
		// EXISTS for every desired sequence — idempotent on the database
		// side but pollutes pendingOperations and the migration plan.
		if obs, ok := obsSeqs[s.Name]; ok && sequenceMatches(obs, dt, inc, s) {
			// OwnedBy is owned by ALTER SEQUENCE which is not idempotent
			// in the same way; keeping that path runs separately below.
			if s.OwnedBy != "" {
				// Even when the sequence body matches we don't currently
				// inspect pg_depend for OWNED BY, so re-emitting ALTER
				// SEQUENCE OWNED BY would be a false positive. PG treats
				// `ALTER SEQUENCE ... OWNED BY x.y` idempotently when the
				// owner is unchanged so this is safe to keep emitting,
				// but for now skip it to avoid false drift counters.
			}
			continue
		}

		var b strings.Builder
		fmt.Fprintf(&b, "CREATE SEQUENCE IF NOT EXISTS %s AS %s INCREMENT BY %d",
			qualified, dt, inc)
		if s.MinValue != 0 {
			fmt.Fprintf(&b, " MINVALUE %d", s.MinValue)
		}
		if s.MaxValue != 0 {
			fmt.Fprintf(&b, " MAXVALUE %d", s.MaxValue)
		}
		if s.StartWith != 0 {
			fmt.Fprintf(&b, " START WITH %d", s.StartWith)
		}

		plan.emit(b.String(), fmt.Sprintf("DROP SEQUENCE IF EXISTS %s", qualified))

		if s.OwnedBy != "" {
			plan.emit(
				fmt.Sprintf("ALTER SEQUENCE %s OWNED BY %s.%s",
					qualified, pg.QuoteIdentifier(schema), s.OwnedBy),
				fmt.Sprintf("ALTER SEQUENCE %s OWNED BY NONE", qualified),
			)
		}
	}
}

// sequenceMatches returns true when the observed sequence is semantically
// equivalent to the desired sequence body (excluding OwnedBy which the
// inspector doesn't currently capture). Compared fields:
//
//   - DataType         case-insensitive (smallint/integer/bigint)
//   - IncrementBy      exact int64
//   - MinValue         non-default match (0 means PG default; treated
//     equivalent to PG-canonical 1 for ASC and
//     MIN_INT for DESC)
//   - MaxValue         non-default match (0 means PG default)
//   - StartValue       non-default match (0 means PG default)
//
// PG-canonical defaults for an ASC bigint sequence: MIN=1,
// MAX=9223372036854775807, START=1. The inspector returns those
// concrete values; the desired side may have 0 to mean "use PG
// default" — equivalence requires special-case treatment.
func sequenceMatches(observed drift.SeqShape, desiredDT string, desiredInc int64,
	s keystonev1alpha1.DesiredSequence) bool {

	if !strings.EqualFold(observed.DataType, desiredDT) {
		return false
	}
	if observed.IncrementBy != desiredInc {
		return false
	}
	if !sequenceBoundEqual(observed.MinValue, s.MinValue, desiredDT, "min", desiredInc > 0) {
		return false
	}
	if !sequenceBoundEqual(observed.MaxValue, s.MaxValue, desiredDT, "max", desiredInc > 0) {
		return false
	}
	if !sequenceBoundEqual(observed.StartValue, s.StartWith, desiredDT, "start", desiredInc > 0) {
		return false
	}
	return true
}

// sequenceBoundEqual treats a desired value of 0 as "PG default" and
// returns true if the observed value matches that default. Otherwise
// requires exact match.
func sequenceBoundEqual(observed, desired int64, dataType, kind string, ascending bool) bool {
	if desired != 0 {
		return observed == desired
	}
	// Desired wants PG default — check if observed equals PG canonical
	// default for this datatype + direction + bound kind.
	dt := strings.ToLower(dataType)
	var maxVal, minVal int64
	switch dt {
	case "smallint":
		maxVal, minVal = 32767, -32768
	case "integer":
		maxVal, minVal = 2147483647, -2147483648
	default: // bigint
		maxVal, minVal = 9223372036854775807, -9223372036854775808
	}
	switch kind {
	case "min":
		if ascending {
			return observed == 1
		}
		return observed == minVal
	case "max":
		if ascending {
			return observed == maxVal
		}
		return observed == -1
	case "start":
		if ascending {
			return observed == 1
		}
		return observed == maxVal
	}
	return false
}

// --- View diffing ---

func diffViews(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Index observed views by name with their reconstructed body.
	obsViews := make(map[string]string, 4)
	for _, t := range observed.Tables {
		if t.Kind == "VIEW" {
			obsViews[t.Name] = t.ViewDefinition
		}
	}

	for _, v := range desired.Views {
		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(v.Name))

		// Empty-query guard: a view with no SELECT body would render as
		// `CREATE OR REPLACE VIEW "x" AS ;` which PG rejects with
		// `syntax error at or near ";"`. Phase F's curate.py stripped
		// these from authored SDs;
		// keystonectl's --strip-dangling-refs absorbed the rule (Phase G,
		// a later phase). But neither pass
		// catches a hand-authored SD that landed an empty query AFTER
		// inspection, AND the differ should fail closed regardless of
		// whether the curation step ran. Skip-with-warning instead of
		// emitting invalid SQL — observed 2026-05-06 on a
		// example-service-public-desired bundle that halted apply at index 1
		// because of 6 such empty-view rows.
		if strings.TrimSpace(v.Query) == "" {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"view %s has empty query; skipped to avoid emitting invalid `CREATE OR REPLACE VIEW … AS ;`. "+
					"Either remove the row from spec.views or fill in the SELECT body.", v.Name))
			continue
		}

		obsDef, exists := obsViews[v.Name]
		if !exists {
			// View doesn't exist yet — CREATE.
			plan.emit(
				fmt.Sprintf("CREATE OR REPLACE VIEW %s AS %s", qualified, v.Query),
				fmt.Sprintf("DROP VIEW IF EXISTS %s", qualified),
			)
			continue
		}

		// Skip emit when the view body already matches. PG's
		// information_schema.views.view_definition reconstructs the
		// SELECT in canonical form (always quoted identifiers, fully-
		// qualified column refs, trailing semicolon). Our renderer
		// emits the user's raw v.Query. normaliseViewBody handles
		// both shapes by stripping bare-identifier quotes and the
		// trailing semicolon before comparing.
		if normaliseViewBody(obsDef) == normaliseViewBody(v.Query) {
			continue
		}

		if v.Replace {
			plan.emit(
				fmt.Sprintf("CREATE OR REPLACE VIEW %s AS %s", qualified, v.Query),
				fmt.Sprintf("DROP VIEW IF EXISTS %s", qualified),
			)
		} else {
			// View exists with different body and Replace=false: warn,
			// don't overwrite.
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"view %s exists with different body; set replace=true to update it", v.Name))
		}
	}
}

// normaliseViewBody normalises a view's SELECT body for equality
// comparison. PG's information_schema.views.view_definition reconstructs
// every view from its parse tree, producing a canonical form with full
// identifier quoting, schema qualification, and a trailing semicolon
// — even when the user's CREATE VIEW statement had none of that. Our
// renderer emits the raw user query verbatim. normaliseViewBody strips
// the cosmetic differences so semantic equivalence wins.
func normaliseViewBody(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")
	s = strings.TrimSpace(s)
	return normaliseDDL(s)
}

// --- Function diffing ---

func diffFunctions(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Index observed functions by name. Functions can be overloaded by
	// argument signature in PG; the inspector's query already filters
	// to one schema, but distinct overloads share a name. Key by
	// (name, args) for correct matching.
	obsFuncs := make(map[string]drift.FuncShape, len(observed.Functions))
	for _, f := range observed.Functions {
		obsFuncs[f.Name+"("+f.Args+")"] = f
	}

	for _, f := range desired.Functions {
		// Skip emit when an equivalent function already exists.
		if obs, ok := obsFuncs[f.Name+"("+f.Args+")"]; ok && functionMatches(obs, f) {
			continue
		}

		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(f.Name))

		lang := f.Language
		if lang == "" {
			lang = "plpgsql"
		}

		// PG's `CREATE FUNCTION ... LANGUAGE c` requires the apply user
		// to be a PG superuser — the migration runner connects as the
		// per-schema `_owner` role which deliberately doesn't have
		// superuser. The DDL hard-fails with SQLSTATE 42501 "permission
		// denied for language c" and the entire bundle aborts.
		//
		// LANGUAGE c functions are also non-portable (rely on shared
		// libraries on the PG server's filesystem), so they shouldn't
		// be in a declarative SchemaDefinition in the first place. Skip
		// with a Warning so the operator sees the problem in
		// SchemaDefinition.status; the function authoring belongs in a
		// hand-written migration that runs as superuser via DBA, not
		// in the declarative diff path.
		if strings.EqualFold(strings.TrimSpace(lang), "c") {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"function %s skipped: LANGUAGE c is not supported in the declarative "+
					"diff (requires PG superuser, non-portable). Move this function to "+
					"a hand-authored migration bundle that runs as a DBA-privileged role.",
				f.Name))
			continue
		}

		var createVerb string
		if f.Replace {
			createVerb = "CREATE OR REPLACE"
		} else {
			createVerb = "CREATE"
		}

		args := f.Args
		createSQL := fmt.Sprintf("%s FUNCTION %s(%s) RETURNS %s LANGUAGE %s AS $fn$%s$fn$",
			createVerb, qualified, args, f.Returns, lang, f.Body)

		dropSQL := fmt.Sprintf("DROP FUNCTION IF EXISTS %s(%s)", qualified, args)
		plan.emit(createSQL, dropSQL)
	}
}

// functionMatches returns true when the observed function from
// pg_get_functiondef is semantically equivalent to the desired
// function. Compared fields:
//
//   - Args                exact (PG returns canonical signature)
//   - Returns             whitespace-normalised
//   - Language            case-insensitive
//   - Body                whitespace-normalised, dollar-quote stripped
//
// pg_get_functiondef wraps the body in `$function$...$function$` (or
// some other dollar-quote tag if the body itself contains the default).
// Our renderer wraps in `$fn$...$fn$`. extractFunctionBody pulls just
// the body out for content comparison.
func functionMatches(observed drift.FuncShape, desired keystonev1alpha1.DesiredFunction) bool {
	if observed.Args != desired.Args {
		return false
	}
	if strings.TrimSpace(strings.ToLower(observed.Returns)) !=
		strings.TrimSpace(strings.ToLower(desired.Returns)) {
		return false
	}
	desiredLang := desired.Language
	if desiredLang == "" {
		desiredLang = "plpgsql"
	}
	if !strings.EqualFold(observed.Language, desiredLang) {
		return false
	}
	obsBody := extractFunctionBody(observed.Definition)
	desiredBody := strings.TrimSpace(desired.Body)
	if normaliseFunctionBody(obsBody) != normaliseFunctionBody(desiredBody) {
		return false
	}
	return true
}

// extractFunctionBody pulls the body out of a CREATE FUNCTION DDL
// produced by pg_get_functiondef. The body is enclosed in matching
// dollar-quote markers (PG picks `$function$` by default, falling
// back to `$function_a$`, `$function_b$`, ... if the body contains
// the default tag literal). Returns the body content with surrounding
// whitespace trimmed; returns the input unchanged if no dollar-quoted
// section is found.
func extractFunctionBody(def string) string {
	// Find the first dollar-quote opening tag in the def. PG always
	// places the body after AS but the AS keyword may be preceded by
	// any whitespace (newline, tab, space) and surrounded by varied
	// case — looking directly for the dollar-quote opener avoids the
	// fragility of finding the AS boundary.
	openStart := strings.Index(def, "$")
	if openStart < 0 {
		return def
	}
	openEnd := strings.Index(def[openStart+1:], "$")
	if openEnd < 0 {
		return def
	}
	tag := def[openStart : openStart+openEnd+2] // `$function$` etc.
	bodyStart := openStart + openEnd + 2
	closeIdx := strings.Index(def[bodyStart:], tag)
	if closeIdx < 0 {
		return def
	}
	return strings.TrimSpace(def[bodyStart : bodyStart+closeIdx])
}

// normaliseFunctionBody lowercases and collapses whitespace for
// content comparison.
func normaliseFunctionBody(s string) string {
	s = strings.ToLower(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// --- Table diffing (full: columns + indexes + FKs) ---

func diffTableFull(
	plan *Plan,
	schema string,
	observed drift.TableShape,
	desired keystonev1alpha1.DesiredTable,
	obsIndexes []drift.ObjectDDL,
	obsConstraints []drift.ObjectDDL,
	obsTableNames map[string]struct{},
) {
	qualified := fmt.Sprintf("%s.%s",
		pg.QuoteIdentifier(schema), pg.QuoteIdentifier(desired.Name))

	// --- Column diff ---
	obsCols := indexObservedColumns(observed.Columns)
	desCols := indexDesiredColumns(desired.Columns)

	for _, dc := range desired.Columns {
		oc, ok := obsCols[dc.Name]
		if !ok {
			// New column → ADD COLUMN.
			// IF NOT EXISTS: re-applying a bundle that was partially
			// applied (or applying after a manual ADD COLUMN that
			// inserted the same column) must converge to desired.
			// IF EXISTS on reverse: symmetric.
			plan.emit(
				fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s",
					qualified, renderColumnDef(dc)),
				fmt.Sprintf("ALTER TABLE %s DROP COLUMN IF EXISTS %s",
					qualified, pg.QuoteIdentifier(dc.Name)),
			)
			continue
		}
		// Existing column → check nullability + default drift.
		if oc.Nullable && !dc.Nullable {
			// Becoming NOT NULL. If a DEFAULT is provided, emit a
			// three-step backfill: SET DEFAULT → UPDATE NULLs → SET NOT NULL.
			if dc.Default != "" {
				// Step 1: Set default first (fast, no lock).
				if !defaultsEqual(dc.Default, oc.Default) {
					plan.emit(
						fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s",
							qualified, pg.QuoteIdentifier(dc.Name), dc.Default),
						fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT",
							qualified, pg.QuoteIdentifier(dc.Name)),
					)
				}
				// Step 2: Backfill existing NULL rows.
				plan.emit(
					fmt.Sprintf("UPDATE %s SET %s = %s WHERE %s IS NULL",
						qualified, pg.QuoteIdentifier(dc.Name),
						dc.Default, pg.QuoteIdentifier(dc.Name)),
					"", // backfill is not reversible (data was NULL)
				)
				// Step 3: Now it's safe to SET NOT NULL.
				plan.emit(
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET NOT NULL",
						qualified, pg.QuoteIdentifier(dc.Name)),
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s DROP NOT NULL",
						qualified, pg.QuoteIdentifier(dc.Name)),
				)
			} else {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf(
					"column %s.%s becoming NOT NULL without DEFAULT — "+
						"will fail if existing rows have NULL",
					desired.Name, dc.Name))
				plan.emit(
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET NOT NULL",
						qualified, pg.QuoteIdentifier(dc.Name)),
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s DROP NOT NULL",
						qualified, pg.QuoteIdentifier(dc.Name)),
				)
			}
		} else if !oc.Nullable && dc.Nullable {
			// PK-column guard: PG primary keys are implicitly NOT NULL
			// (per SQL standard + PG's pg_constraint logic). Attempting
			// `ALTER TABLE x ALTER COLUMN id DROP NOT NULL` on a PK
			// column fails with SQLSTATE 42P16 "column X is in a
			// primary key". The differ should not emit DROP NOT NULL
			// against a column that's part of the primary key — the
			// declaration `Nullable: true` on a PK column is itself a
			// schema-authoring error (PG semantics make a NULLable PK
			// impossible), but the differ shouldn't crash the whole
			// bundle on it. Skip + warn so the SchemaDefinition author
			// sees the gap.
			if isPrimaryKeyColumn(dc.Name, &desired) {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf(
					"column %s.%s declared Nullable=true but is in the "+
						"primary key; PG implicitly enforces NOT NULL on "+
						"PK columns — DROP NOT NULL would fail SQLSTATE "+
						"42P16. Either remove the column from primaryKey "+
						"or set Nullable=false in spec.",
					desired.Name, dc.Name))
			} else {
				plan.emit(
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s DROP NOT NULL",
						qualified, pg.QuoteIdentifier(dc.Name)),
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET NOT NULL",
						qualified, pg.QuoteIdentifier(dc.Name)),
				)
			}
		} else {
			// No nullability change — still diff defaults.
			if dc.Default != "" && !defaultsEqual(dc.Default, oc.Default) {
				oldDefault := oc.Default
				reverse := fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT",
					qualified, pg.QuoteIdentifier(dc.Name))
				if oldDefault != "" {
					reverse = fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s",
						qualified, pg.QuoteIdentifier(dc.Name), oldDefault)
				}
				plan.emit(
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s",
						qualified, pg.QuoteIdentifier(dc.Name), dc.Default),
					reverse,
				)
			} else if dc.Default == "" && oc.Default != "" && !defaultsEqual(dc.Default, oc.Default) {
				plan.emit(
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT",
						qualified, pg.QuoteIdentifier(dc.Name)),
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s",
						qualified, pg.QuoteIdentifier(dc.Name), oc.Default),
				)
			}
		}

		// Column TYPE drift: warn, don't emit.
		//
		// information_schema.data_type returns the descriptive label
		// "ARRAY" / "USER-DEFINED" for those families — the actual
		// element/UDT name lives in udt_name. ResolveColumnType is the
		// shared canonicaliser keystonectl uses at SD-render time, so
		// comparing against the resolved form matches what users author
		// (e.g. "text[]", "tenant_type") instead of false-positiving on
		// every reconcile.
		observedType := drift.ResolveColumnTypeShape(oc)
		if string(dc.Type) != observedType {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"column %s.%s type drift: observed=%s desired=%s — "+
					"type changes require pgroll-expand-contract "+
					"alter_column_type; NOT emitted",
				desired.Name, dc.Name, observedType, dc.Type))
		}
	}

	// Columns in observed but not desired → DROP COLUMN.
	for _, oc := range observed.Columns {
		if _, ok := desCols[oc.Name]; ok {
			continue
		}
		plan.emitDestructive(
			// IF EXISTS: must not fail on second-apply when the column
			// has already been dropped (or never existed due to drift).
			fmt.Sprintf("ALTER TABLE %s DROP COLUMN IF EXISTS %s",
				qualified, pg.QuoteIdentifier(oc.Name)),
			"", // not reversible — data loss
		)
	}

	diffTableObjects(plan, schema, desired, obsIndexes, obsConstraints, obsTableNames)
}

// diffTableObjects emits the index, foreign-key, and CHECK-constraint
// diffs for one table. Factored out of diffTableFull so the same logic
// can also run for brand-new tables created earlier in this diff: pass
// nil observed slices and every desired object is emitted as a create
// (renderCreateTable only emits columns + the primary key, so without
// this a fresh table would silently lose its indexes and foreign keys).
// Idempotency guards (IF EXISTS reverses, DO-block existence checks) are
// preserved so re-applying a partially-applied bundle still converges.
func diffTableObjects(
	plan *Plan,
	schema string,
	desired keystonev1alpha1.DesiredTable,
	obsIndexes []drift.ObjectDDL,
	obsConstraints []drift.ObjectDDL,
	obsTableNames map[string]struct{},
) {
	qualified := fmt.Sprintf("%s.%s",
		pg.QuoteIdentifier(schema), pg.QuoteIdentifier(desired.Name))

	// --- Index diff (now using full snapshot indexes) ---
	//
	// The indexes backing a PRIMARY KEY or UNIQUE constraint are excluded
	// from the observed set, because the desired set never contains them:
	// schemaspec carries those constraints as constraints. Leaving them in
	// makes every one look like an index the user deleted, and the diff
	// emits `DROP INDEX` for the index a live constraint depends on —
	// which PostgreSQL refuses ("cannot drop index ... because constraint
	// ... requires it"), so the whole migration fails rather than just
	// that statement.
	//
	// PostgreSQL always names a constraint's backing index after the
	// constraint, so the constraint list is the exact filter.
	constraintBackedIdx := map[string]bool{}
	for _, c := range obsConstraints {
		if c.Table != desired.Name {
			continue
		}
		if c.Type == "PRIMARY KEY" || c.Type == "UNIQUE" {
			constraintBackedIdx[c.Name] = true
		}
	}
	obsIdxMap := map[string]drift.ObjectDDL{}
	for _, idx := range obsIndexes {
		if constraintBackedIdx[idx.Name] {
			continue
		}
		obsIdxMap[idx.Name] = idx
	}

	// Desired indexes: CREATE INDEX CONCURRENTLY for new ones.
	for _, dIdx := range desired.Indexes {
		oIdx, exists := obsIdxMap[dIdx.Name]
		if !exists {
			fwd := renderCreateIndexConcurrently(schema, desired.Name, dIdx)
			plan.emit(fwd,
				fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %s.%s",
					pg.QuoteIdentifier(schema), pg.QuoteIdentifier(dIdx.Name)))
			continue
		}
		// Exists — check if definition matches.
		expected := renderCreateIndex(schema, desired.Name, dIdx)
		if !indexDDLMatch(oIdx.Definition, expected) {
			plan.emitDestructive(
				// IF EXISTS: re-applying a bundle that's already
				// rotated this index (or the index was dropped
				// out-of-band) must not throw `index X does not exist`.
				fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %s.%s",
					pg.QuoteIdentifier(schema), pg.QuoteIdentifier(dIdx.Name)),
				"", // will be re-created next
			)
			plan.emit(
				renderCreateIndexConcurrently(schema, desired.Name, dIdx),
				fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %s.%s",
					pg.QuoteIdentifier(schema), pg.QuoteIdentifier(dIdx.Name)),
			)
		}
	}

	// Indexes in observed but not desired → DROP INDEX CONCURRENTLY.
	desIdxByName := indexDesiredByName(desired.Indexes)
	for name := range obsIdxMap {
		if _, ok := desIdxByName[name]; ok {
			continue
		}
		if strings.HasSuffix(name, "_pkey") {
			continue
		}
		plan.emitDestructive(
			// IF EXISTS — must not fail on second-apply when the
			// index has already been dropped (manual cleanup,
			// prior partial apply, etc.).
			fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %s.%s",
				pg.QuoteIdentifier(schema), pg.QuoteIdentifier(name)),
			"", // original DDL unknown for rebuild
		)
	}

	// --- FK constraint diff ---
	obsFKs := map[string]drift.ObjectDDL{}
	for _, c := range obsConstraints {
		if c.Type == "FOREIGN KEY" {
			obsFKs[c.Name] = c
		}
	}

	desFKs := map[string]keystonev1alpha1.DesiredForeignKey{}
	for _, fk := range desired.ForeignKeys {
		desFKs[fk.Name] = fk
	}

	// Build a set of known tables for FK target validation. Union
	// of observed.Tables names — diffTableFull doesn't see other
	// tables in the same diff, so we rely on the observed snapshot
	// alone for cross-table FK target presence. A target table in
	// desired-but-not-observed would be created in the same diff
	// (earlier wave); since diffTableFull runs per-table after the
	// CREATE TABLE wave, the desired target IS observed-side
	// reachable by then.

	// New FKs: two-phase ADD NOT VALID → VALIDATE.
	//
	// The ADD is wrapped in a DO block with IF NOT EXISTS so it stays
	// idempotent even when:
	//
	//   - the inspect cache is stale (inspect ran before a prior
	//     reconcile's partial apply created some constraints);
	//   - apply runs against a schema where the constraint was already
	//     created out-of-band (manual psql, prior tooling);
	//   - a prior ME apply was killed mid-flight after the ADD ran but
	//     before the bundle status patch flipped to Succeeded —
	//     re-applying the same bundle would re-issue the ADD and
	//     crash with SQLSTATE 42710 ("constraint already exists"),
	//     blocking convergence.
	//
	// The non-DO-block form behaves identically when the constraint
	// is genuinely missing; when present it short-circuits with a
	// no-op rather than an error. Same pattern as EnsureRole's
	// existence-guarded CREATE ROLE in internal/postgres/admin.go.
	//
	// VALIDATE is left as a bare statement because it is idempotent
	// in PostgreSQL — re-running on an already-VALID constraint is a
	// no-op, not an error.
	for _, fk := range desired.ForeignKeys {
		if _, exists := obsFKs[fk.Name]; exists {
			continue
		}
		// FK target validation: if the referenced table isn't in the
		// observed snapshot AND isn't otherwise known to be in
		// desired (we can't easily access top-level diff state here,
		// but the wave order — CREATE TABLE before FK constraints —
		// means by FK-emit time, all CREATE TABLE statements have
		// already been queued in plan.Statements; the apply itself
		// runs them in order, so target table will exist at apply
		// time if it's in desired).
		//
		// Therefore: only ERROR out if the target is neither in
		// observed NOR in plan.Statements (i.e. neither live nor
		// being created). For the example-service-tenant case where
		// `iam_licenses` FK target had been removed from the
		// SchemaDefinition's tables list but the FK declaration
		// still pointed at it, this catches the orphan FK and
		// skips with a Warning rather than failing the bundle.
		//
		// Note: this guard only checks the same-schema target
		// (REFERENCES %s.%s uses `schema` for the target schema).
		// Cross-schema FKs would need a different mechanism;
		// out-of-scope for this fix.
		if !tableReachable(fk.ReferencesTable, plan, schema, obsTableNames) {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"foreign key %s on %s.%s skipped: target table "+
					"%q is neither in observed nor being created in "+
					"this diff. Either add the table to spec.tables "+
					"or remove the FK declaration.",
				fk.Name, schema, desired.Name, fk.ReferencesTable))
			continue
		}
		onDelete := fk.OnDelete
		if onDelete == "" {
			onDelete = "NO ACTION"
		}
		addInner := fmt.Sprintf(
			"ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s.%s (%s) ON DELETE %s NOT VALID",
			qualified, pg.QuoteIdentifier(fk.Name),
			quoteList(fk.Columns),
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(fk.ReferencesTable),
			quoteList(fk.ReferencesColumns),
			onDelete)
		// Use a DO block with a pg_constraint existence check to make
		// the ADD idempotent. conrelid is matched via regclass to scope
		// the lookup to the exact table — constraint names are unique
		// per-table in PG, so name+conrelid is the natural key.
		addSQL := fmt.Sprintf(
			`DO $$ BEGIN
				IF NOT EXISTS (
					SELECT 1 FROM pg_constraint
					 WHERE conname = %s
					   AND conrelid = %s::regclass
				) THEN
					%s;
				END IF;
			END $$`,
			pg.QuoteString(fk.Name),
			pg.QuoteString(qualified),
			addInner,
		)
		plan.emit(addSQL,
			// IF EXISTS on reverse: re-applying past a partial-apply
			// where the FK was created on forward but the bundle
			// failed before VALIDATE must not fail to roll back.
			fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s",
				qualified, pg.QuoteIdentifier(fk.Name)))

		// VALIDATE in a separate statement — takes ShareUpdateExclusiveLock
		// (non-blocking reads/writes). Idempotent: re-running on an
		// already-VALID constraint is a no-op in PostgreSQL.
		plan.emit(
			fmt.Sprintf("ALTER TABLE %s VALIDATE CONSTRAINT %s",
				qualified, pg.QuoteIdentifier(fk.Name)),
			"", // validation is idempotent
		)
	}

	// FKs in observed but not desired → DROP CONSTRAINT.
	for name := range obsFKs {
		if _, ok := desFKs[name]; ok {
			continue
		}
		plan.emitDestructive(
			// IF EXISTS — must not fail on second-apply when the FK
			// has already been dropped. This eliminates the bulk of
			// the 7× "constraint X for relation Y" failures observed
			// live on example-service-{public,control} 2026-05-18.
			fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s",
				qualified, pg.QuoteIdentifier(name)),
			"", // original FK definition not easily reconstructed
		)
	}

	// --- CHECK constraint diff ---
	//
	// Match strictly by name+table. We do NOT compare definition text
	// because pg_get_constraintdef() canonicalises expressions in
	// ways that don't survive a textual round-trip from the YAML
	// (operator/cast spelling, parenthesisation, etc.), so any
	// equality check on `Definition` would produce false positives
	// against perfectly applied constraints. Trade-off: if the user
	// edits a CHECK predicate in-place without renaming, the differ
	// won't notice. Practical workaround: rename the constraint
	// (drop old name + add new name) — the version-suffix idiom in
	// production schemas already does this for shape changes.
	obsChks := map[string]drift.ObjectDDL{}
	for _, c := range obsConstraints {
		if c.Type == "CHECK" && c.Table == desired.Name {
			obsChks[c.Name] = c
		}
	}
	desChks := map[string]keystonev1alpha1.DesiredCheckConstraint{}
	for _, cc := range desired.CheckConstraints {
		desChks[cc.Name] = cc
	}

	// New CHECK constraints: two-phase ADD NOT VALID → VALIDATE,
	// mirroring the FK pattern so partial-apply convergence works.
	// pg_constraint existence guard avoids 42710 on re-apply.
	for _, cc := range desired.CheckConstraints {
		if _, exists := obsChks[cc.Name]; exists {
			continue
		}
		addInner := fmt.Sprintf(
			"ALTER TABLE %s ADD CONSTRAINT %s CHECK (%s) NOT VALID",
			qualified, pg.QuoteIdentifier(cc.Name), cc.Definition)
		addSQL := fmt.Sprintf(
			`DO $$ BEGIN
				IF NOT EXISTS (
					SELECT 1 FROM pg_constraint
					 WHERE conname = %s
					   AND conrelid = %s::regclass
				) THEN
					%s;
				END IF;
			END $$`,
			pg.QuoteString(cc.Name),
			pg.QuoteString(qualified),
			addInner,
		)
		plan.emit(addSQL,
			fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s",
				qualified, pg.QuoteIdentifier(cc.Name)))

		// VALIDATE in a separate statement — takes
		// ShareUpdateExclusiveLock (non-blocking reads/writes).
		// Idempotent: re-running on an already-VALID constraint is
		// a no-op in PostgreSQL.
		plan.emit(
			fmt.Sprintf("ALTER TABLE %s VALIDATE CONSTRAINT %s",
				qualified, pg.QuoteIdentifier(cc.Name)),
			"", // validation is idempotent
		)
	}

	// CHECKs in observed but not desired → DROP CONSTRAINT (destructive).
	for name := range obsChks {
		if _, ok := desChks[name]; ok {
			continue
		}
		plan.emitDestructive(
			fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s",
				qualified, pg.QuoteIdentifier(name)),
			"", // original CHECK definition not easily reconstructed
		)
	}

	// --- UNIQUE constraint diff ---
	//
	// Emitted as ALTER TABLE ADD CONSTRAINT rather than folded into the
	// CREATE TABLE body, matching how CHECKs and FKs are handled: the
	// CREATE renderer's trailing-comma bookkeeping around the optional
	// PRIMARY KEY line has already produced invalid SQL once, and a
	// second optional clause there would widen that surface for no gain.
	//
	// Matched by name, like CHECKs. A change to the column list or to
	// NULLS NOT DISTINCT under the same name is not detected — rename the
	// constraint to express a shape change, which is the same idiom the
	// CHECK path documents.
	obsUniq := map[string]drift.ObjectDDL{}
	for _, c := range obsConstraints {
		if c.Type == "UNIQUE" && c.Table == desired.Name {
			obsUniq[c.Name] = c
		}
	}
	desUniq := map[string]keystonev1alpha1.DesiredUniqueConstraint{}
	for _, uc := range desired.UniqueConstraints {
		desUniq[uc.Name] = uc
	}

	for _, uc := range desired.UniqueConstraints {
		if _, exists := obsUniq[uc.Name]; exists {
			continue
		}
		if len(uc.Columns) == 0 {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("unique constraint %q on %s declares no columns; skipped",
					uc.Name, desired.Name))
			continue
		}
		nulls := ""
		if uc.NullsNotDistinct {
			nulls = " NULLS NOT DISTINCT"
		}
		addInner := fmt.Sprintf(
			"ALTER TABLE %s ADD CONSTRAINT %s UNIQUE%s (%s)",
			qualified, pg.QuoteIdentifier(uc.Name), nulls, quoteList(uc.Columns))
		// pg_constraint existence guard, as for CHECKs: adding a
		// constraint that already exists raises 42710, and a re-applied
		// migration must be a no-op.
		//
		// Not split into ADD NOT VALID + VALIDATE the way CHECK and FK
		// are: PostgreSQL has no NOT VALID for UNIQUE — it must build the
		// backing index to prove uniqueness — so the two-phase form is
		// simply not available here.
		plan.emit(
			fmt.Sprintf(
				`DO $$ BEGIN
				IF NOT EXISTS (
					SELECT 1 FROM pg_constraint
					 WHERE conname = %s
					   AND conrelid = %s::regclass
				) THEN
					%s;
				END IF;
			END $$`,
				pg.QuoteString(uc.Name), pg.QuoteString(qualified), addInner),
			fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s",
				qualified, pg.QuoteIdentifier(uc.Name)))
	}

	// UNIQUEs in observed but not desired → DROP CONSTRAINT (destructive:
	// it drops the backing index and the uniqueness guarantee with it).
	for name := range obsUniq {
		if _, ok := desUniq[name]; ok {
			continue
		}
		plan.emitDestructive(
			fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s",
				qualified, pg.QuoteIdentifier(name)),
			"", // original column list not reconstructed from the drop
		)
	}
}

// --- Topological sort for CREATE TABLE ---

// topoSortTables returns table names in FK dependency order (parents
// before children). Falls back to alphabetical for tables with no FKs
// or cycles (cycles are warned about but not fatal — PG can handle
// deferred FKs).
func topoSortTables(tables []keystonev1alpha1.DesiredTable) (result []string, hasCycle bool) {
	names := make(map[string]bool, len(tables))
	for _, t := range tables {
		names[t.Name] = true
	}

	// Build adjacency: child → set of parents (FK references).
	deps := make(map[string]map[string]bool, len(tables))
	for _, t := range tables {
		deps[t.Name] = map[string]bool{}
		for _, fk := range t.ForeignKeys {
			// Only add dependency if the referenced table is in our set
			// and is not self-referential.
			if names[fk.ReferencesTable] && fk.ReferencesTable != t.Name {
				deps[t.Name][fk.ReferencesTable] = true
			}
		}
	}

	// Kahn's algorithm — compute in-degree (number of FK parents each
	// table depends on).
	inDegree := make(map[string]int, len(tables))
	for _, t := range tables {
		inDegree[t.Name] = 0
	}
	for child, parents := range deps {
		inDegree[child] += len(parents)
	}

	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue) // deterministic tie-breaking

	for len(queue) > 0 {
		// Pop front.
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		// Find children of this node (tables that depend on it).
		for child, parents := range deps {
			if parents[node] {
				inDegree[child]--
				if inDegree[child] == 0 {
					queue = append(queue, child)
					sort.Strings(queue)
				}
			}
		}
	}

	// Handle cycles: any remaining tables not in result.
	if len(result) < len(tables) {
		remaining := make([]string, 0)
		inResult := make(map[string]bool, len(result))
		for _, n := range result {
			inResult[n] = true
		}
		for _, t := range tables {
			if !inResult[t.Name] {
				remaining = append(remaining, t.Name)
			}
		}
		sort.Strings(remaining)
		result = append(result, remaining...)
		hasCycle = true
	}

	return result, hasCycle
}

// --- RLS diffing ---

// diffRLS converges the two row-level-security bits: relrowsecurity
// (ENABLE) and relforcerowsecurity (FORCE).
//
// Both statements are idempotent in PostgreSQL, so this used to emit them
// for every RLS table unconditionally. That is correct but not honest: a
// schema already in its desired state produced two statements per RLS
// table — 172 for downstream-service — and a plan that is never empty is a plan
// nobody reads closely. Now that the observed snapshot carries the FORCE
// bit, both can be compared, and an unchanged schema plans to nothing.
//
// Unknown counts as "needs the statement": a table absent from observed is
// being created by this same plan, and a nil RLSForced comes from a
// snapshot written before the field existed. Emitting there is the old
// behaviour and is harmless.
//
// Note the deliberate asymmetry: nothing here ever emits DISABLE ROW LEVEL
// SECURITY. Clearing spec.tables[].enableRLS skips the table entirely
// rather than turning RLS off on a live one. Un-forcing is different — it
// is reachable, because a declaration that says forceRLS: false and a
// database that ignores it is the drift this whole path exists to close —
// but it goes through emitDestructive, so it is refused outright unless
// the SchemaDefinition sets allowDestructive, and gated on approval when
// it does. Dropping the owner's exemption from every policy on a
// multi-tenant table is a cross-tenant exposure, not a schema tweak.
func diffRLS(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Reads on a nil map are fine; observed is only nil in unit tests, and
	// there "unknown" is exactly the right answer.
	var obs map[string]drift.TableShape
	if observed != nil {
		obs = observedTables(observed)
	}

	for _, t := range desired.Tables {
		if !t.EnableRLS {
			continue
		}
		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(t.Name))

		cur, known := obs[t.Name]

		if !known || !cur.RLSEnabled {
			plan.emit(
				fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", qualified),
				fmt.Sprintf("ALTER TABLE %s DISABLE ROW LEVEL SECURITY", qualified),
			)
		}

		// Unset means forced — what this emitted unconditionally before
		// spec.tables[].forceRLS existed, so existing SchemaDefinitions are
		// unaffected.
		wantForced := t.ForceRLS == nil || *t.ForceRLS

		var curForced *bool
		if known {
			curForced = cur.RLSForced
		}

		switch {
		case wantForced && (curForced == nil || !*curForced):
			plan.emit(
				fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", qualified),
				fmt.Sprintf("ALTER TABLE %s NO FORCE ROW LEVEL SECURITY", qualified),
			)
		case !wantForced && (curForced == nil || *curForced):
			plan.emitDestructive(
				fmt.Sprintf("ALTER TABLE %s NO FORCE ROW LEVEL SECURITY", qualified),
				fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", qualified),
			)
		}
	}
}

// --- Materialized view diffing ---

func diffMaterializedViews(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Index observed matviews by name with their definitions.
	obsMVs := make(map[string]string, len(observed.MaterializedViews))
	for _, mv := range observed.MaterializedViews {
		obsMVs[mv.Name] = mv.Definition
	}

	for _, mv := range desired.MaterializedViews {
		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(mv.Name))

		withData := "WITH DATA"
		if !mv.WithData {
			withData = "WITH NO DATA"
		}

		// Skip CREATE emit when matview already exists with matching
		// body. Note: CREATE MATERIALIZED VIEW IF NOT EXISTS is not
		// rebuild-on-change — if the body needs to change, an explicit
		// DROP + CREATE is required (which would lose data). For now
		// we treat existing matviews as authoritative; future work
		// can add a DROP-and-recreate path gated on AllowDestructive.
		_, exists := obsMVs[mv.Name]
		if !exists {
			// pg_matviews.definition (the source of mv.Query) carries a
			// trailing ";", which would render as "... AS <query>; WITH DATA;"
			// -> the dangling "WITH DATA;" is a syntax error (SQLSTATE 42601).
			// Strip the terminator before composing the CREATE.
			query := strings.TrimRight(strings.TrimSpace(mv.Query), ";")
			plan.emit(
				fmt.Sprintf("CREATE MATERIALIZED VIEW IF NOT EXISTS %s AS %s %s",
					qualified, query, withData),
				fmt.Sprintf("DROP MATERIALIZED VIEW IF EXISTS %s", qualified),
			)
		}

		// Indexes on the materialized view — diffMatViewIndexes path
		// would need its own observed-vs-desired compare; out of scope
		// here. For now, keep emitting (these CREATE INDEX CONCURRENTLY
		// IF NOT EXISTS are idempotent so they don't break anything;
		// they just show as drift).
		for _, idx := range mv.Indexes {
			plan.emit(
				renderCreateIndexConcurrently(schema, mv.Name, idx),
				fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %s.%s",
					pg.QuoteIdentifier(schema), pg.QuoteIdentifier(idx.Name)),
			)
		}
	}
}

// --- Trigger diffing ---

func diffTriggers(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Index observed triggers by (table, name) for O(1) lookup.
	obsTriggers := make(map[string]drift.TriggerShape, len(observed.Triggers))
	for _, t := range observed.Triggers {
		obsTriggers[t.Table+"\x00"+t.Name] = t
	}

	// Index of functions known to exist at apply-time. Union of
	// observed (live DB) and desired (will be created by this diff
	// in an earlier wave — function diffs emit before trigger diffs
	// per the wave order in differ.go's top-level Diff()).
	//
	// Used to guard CREATE TRIGGER emission below: PG fails the
	// apply with SQLSTATE 42883 "function X does not exist" if a
	// trigger references a function that neither live nor diff
	// will produce. Without this guard, 8× failures observed live
	// on example-service-{public,control} 2026-05-18 on triggers
	// referencing `public.log_changes()` — the function had been
	// dropped by an earlier (manual?) cleanup but the trigger
	// definitions remained in observed; SchemaDefinition.spec
	// declared the triggers but NOT the function.
	knownFunctions := make(map[string]struct{})
	for _, of := range observed.Functions {
		knownFunctions[of.Name] = struct{}{}
	}
	for _, df := range desired.Functions {
		// Skip LANGUAGE c — those are dropped above with a Warning;
		// don't count them as available for trigger reference.
		if strings.EqualFold(strings.TrimSpace(df.Language), "c") {
			continue
		}
		knownFunctions[df.Name] = struct{}{}
	}

	for _, tr := range desired.Triggers {
		// Skip emit when an equivalent trigger already exists. The
		// previous unconditional DROP+CREATE generated thousands of
		// no-op operations on every reconcile against a steady-state
		// schema — burning example-pg's pendingOperations counter
		// even though nothing was actually drifting.
		if obs, ok := obsTriggers[tr.Table+"\x00"+tr.Name]; ok && triggerMatches(obs, tr) {
			continue
		}

		// Function-existence guard. If the trigger references a
		// function that neither live nor diff will produce, skip
		// the emit with a Warning. Better to leave the live trigger
		// alone (DROP+CREATE would fail mid-bundle and abort
		// everything downstream) than to brick the whole apply.
		if tr.Function != "" {
			if _, ok := knownFunctions[tr.Function]; !ok {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf(
					"trigger %s on %s skipped: function %q is not in observed nor in "+
						"desired.functions. Add a DesiredFunction for %q to the "+
						"SchemaDefinition spec, or remove the trigger.",
					tr.Name, tr.Table, tr.Function, tr.Function))
				continue
			}
		}

		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(tr.Table))

		events := strings.Join(tr.Events, " OR ")
		forEach := "FOR EACH ROW"
		if !tr.ForEachRow {
			forEach = "FOR EACH STATEMENT"
		}

		var whenClause string
		if tr.When != "" {
			whenClause = fmt.Sprintf(" WHEN (%s)", tr.When)
		}

		// CREATE OR REPLACE TRIGGER (PG 14+) or DROP + CREATE for older.
		// We use DROP IF EXISTS + CREATE for broader compatibility.
		plan.emit(
			fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON %s",
				pg.QuoteIdentifier(tr.Name), qualified),
			"", // dropping the old is part of the create cycle
		)
		plan.emit(
			fmt.Sprintf("CREATE TRIGGER %s %s %s ON %s %s%s EXECUTE FUNCTION %s.%s()",
				pg.QuoteIdentifier(tr.Name),
				tr.Timing, events, qualified,
				forEach, whenClause,
				pg.QuoteIdentifier(schema), pg.QuoteIdentifier(tr.Function)),
			fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON %s",
				pg.QuoteIdentifier(tr.Name), qualified),
		)
	}
}

// triggerMatches returns true when an observed trigger from the live
// database is semantically equivalent to a desired trigger from the
// SchemaDefinition. Compared fields:
//
//   - Name, Table         exact (case-sensitive — PG identifiers)
//   - Timing              case-insensitive (BEFORE/AFTER/INSTEAD OF)
//   - Events              set equality (PG canonicalises ordering)
//   - ForEachRow          exact bool
//   - Function            exact (PG returns proname unqualified)
//   - When                whitespace+identifier-quote normalised
//
// The intent is to be liberal in what we accept as "equal" — the live
// database's pg_get_triggerdef output and our renderer's CREATE TRIGGER
// output have many cosmetic-only differences (event ordering, identifier
// quoting). This match function captures semantic equivalence so the
// differ doesn't emit DROP+CREATE pairs for unchanged triggers.
func triggerMatches(observed drift.TriggerShape, desired keystonev1alpha1.DesiredTrigger) bool {
	if observed.Name != desired.Name || observed.Table != desired.Table {
		return false
	}
	if !strings.EqualFold(observed.Timing, desired.Timing) {
		return false
	}
	if observed.ForEachRow != desired.ForEachRow {
		return false
	}
	if observed.Function != desired.Function {
		return false
	}
	if !stringSetEqualCI(observed.Events, desired.Events) {
		return false
	}
	if normaliseDDL(observed.When) != normaliseDDL(desired.When) {
		return false
	}
	return true
}

// --- RLS policy diffing ---

func diffPolicies(plan *Plan, schema string, observed *drift.Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec) {
	// Index observed policies by (table, name) for O(1) lookup.
	obsPolicies := make(map[string]drift.PolicyShape, len(observed.Policies))
	for _, p := range observed.Policies {
		obsPolicies[p.Table+"\x00"+p.Name] = p
	}

	for _, p := range desired.Policies {
		// Skip emit when an equivalent policy already exists. See
		// triggerMatches commentary; same noisy-no-op problem.
		if obs, ok := obsPolicies[p.Table+"\x00"+p.Name]; ok && policyMatches(obs, p) {
			continue
		}

		qualified := fmt.Sprintf("%s.%s",
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(p.Table))

		cmd := p.Command
		if cmd == "" {
			cmd = "ALL"
		}

		policyType := "PERMISSIVE"
		if !p.Permissive {
			policyType = "RESTRICTIVE"
		}

		roles := "PUBLIC"
		if len(p.Roles) > 0 {
			roles = strings.Join(p.Roles, ", ")
		}

		var clauses []string
		if p.Using != "" {
			clauses = append(clauses, fmt.Sprintf("USING (%s)", p.Using))
		}
		if p.WithCheck != "" {
			clauses = append(clauses, fmt.Sprintf("WITH CHECK (%s)", p.WithCheck))
		}

		// DROP + CREATE for idempotency (CREATE POLICY has no IF NOT EXISTS).
		plan.emit(
			fmt.Sprintf("DROP POLICY IF EXISTS %s ON %s",
				pg.QuoteIdentifier(p.Name), qualified),
			"",
		)
		plan.emit(
			fmt.Sprintf("CREATE POLICY %s ON %s AS %s FOR %s TO %s %s",
				pg.QuoteIdentifier(p.Name), qualified,
				policyType, cmd, roles,
				strings.Join(clauses, " ")),
			fmt.Sprintf("DROP POLICY IF EXISTS %s ON %s",
				pg.QuoteIdentifier(p.Name), qualified),
		)
	}
}

// policyMatches returns true when an observed RLS policy is
// semantically equivalent to a desired policy. Compared fields:
//
//   - Name, Table         exact
//   - Command             case-insensitive (default ALL)
//   - Permissive          exact bool
//   - Roles               set equality (case-insensitive — PG roles
//     are case-folded), empty/PUBLIC equivalent
//   - Using, WithCheck    whitespace+identifier-quote normalised
//
// PG's pg_get_expr(polqual, polrelid) reconstructs the USING clause
// in canonical form (full schema qualification, identifier quoting
// only where required). Our renderer emits the raw user-written
// expression. Both forms must normalise equal for steady-state
// reconcile.
func policyMatches(observed drift.PolicyShape, desired keystonev1alpha1.DesiredPolicy) bool {
	if observed.Name != desired.Name || observed.Table != desired.Table {
		return false
	}
	desiredCmd := desired.Command
	if desiredCmd == "" {
		desiredCmd = "ALL"
	}
	if !strings.EqualFold(observed.Command, desiredCmd) {
		return false
	}
	if observed.Permissive != desired.Permissive {
		return false
	}
	if !rolesEqual(observed.Roles, desired.Roles) {
		return false
	}
	if normaliseDDL(observed.Using) != normaliseDDL(desired.Using) {
		return false
	}
	if normaliseDDL(observed.WithCheck) != normaliseDDL(desired.WithCheck) {
		return false
	}
	return true
}

// stringSetEqualCI reports whether two string slices contain the
// same elements (case-insensitive), regardless of order.
func stringSetEqualCI(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[strings.ToLower(s)]++
	}
	for _, s := range b {
		seen[strings.ToLower(s)]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// rolesEqual treats empty role list, [PUBLIC], and [public] as
// equivalent (PG canonicalises an unspecified TO clause to PUBLIC).
func rolesEqual(a, b []string) bool {
	canon := func(roles []string) []string {
		if len(roles) == 0 {
			return []string{"public"}
		}
		out := make([]string, 0, len(roles))
		for _, r := range roles {
			out = append(out, strings.ToLower(r))
		}
		return out
	}
	return stringSetEqualCI(canon(a), canon(b))
}

// --- Rendering helpers ---

// isPrimaryKeyColumn reports whether `colName` is part of the
// primary key of `t` (either via table-level t.PrimaryKey list
// or via inline c.PrimaryKey on the matching column).
func isPrimaryKeyColumn(colName string, t *keystonev1alpha1.DesiredTable) bool {
	for _, pk := range t.PrimaryKey {
		if pk == colName {
			return true
		}
	}
	for _, c := range t.Columns {
		if c.Name == colName && c.PrimaryKey {
			return true
		}
	}
	return false
}

// tableReachable reports whether `name` is a table that exists in
// the observed snapshot OR is being created by an already-queued
// CREATE TABLE statement in `plan.Statements`. Used by the FK target
// guard in diffTableFull to skip orphan FK declarations rather than
// hard-fail the apply on a missing target table.
//
// Three checks:
//  1. obsTableNames — the observed-snapshot set. Table exists live.
//  2. plan.Statements scan — table is being created earlier in the
//     same diff (CREATE TABLE wave runs before FK constraint wave).
//
// False positives are possible only if a string literal happens to
// contain the exact CREATE TABLE prefix, which doesn't happen with
// well-formed DDL.
func tableReachable(name string, plan *Plan, schema string, obsTableNames map[string]struct{}) bool {
	if _, ok := obsTableNames[name]; ok {
		return true
	}
	prefix := fmt.Sprintf(
		"CREATE TABLE %s.%s (",
		pg.QuoteIdentifier(schema), pg.QuoteIdentifier(name),
	)
	for _, stmt := range plan.Statements {
		if strings.HasPrefix(stmt, prefix) {
			return true
		}
	}
	return false
}

func renderCreateTable(schema string, t keystonev1alpha1.DesiredTable) string {
	// Multiple-PRIMARY-KEY guard: if ≥2 columns carry
	// PrimaryKey:true inline, OR the table-level PrimaryKey list is
	// being rendered (needsPKLine), the inline `PRIMARY KEY` on each
	// column would produce "multiple primary keys for table" (PG
	// error 42P16). User intent in that case is a composite PK —
	// suppress all inline `PRIMARY KEY` and let the table-level
	// constraint (PRIMARY KEY (col1, col2)) be authoritative.
	//
	// Verified live on prod 2026-05-18:
	//   CREATE TABLE iam_oauth_client_trusted_external_issuers (
	//     "client_id" uuid NOT NULL PRIMARY KEY,    -- ← inline #1
	//     "issuer_id" uuid NOT NULL PRIMARY KEY,    -- ← inline #2 → ERROR
	//     ...
	//   )
	// → SQLSTATE 42P16 "multiple primary keys for table".
	//
	// Fix: count inline PKs; if >1 OR if a table-level PK is being
	// emitted, suppress inline. Single-column PK as inline is the
	// canonical shorthand and remains.
	// The PK line is decided once, up front, and everything else reads
	// off it. Previously four conditions (needsPKLine, inlinePKCount > 1,
	// suppressInlinePK, pkLineFollows) each re-derived "is there a
	// table-level PK clause?" from the inputs, and the 42P16 and
	// trailing-comma bugs above were both a case where two of them
	// disagreed. Naming the constraint would have added a fifth.
	pkLine := renderPKLine(t)

	// A trailing comma is required after the last column exactly when a
	// table-level clause follows it, and the inline `PRIMARY KEY`
	// shorthand must be suppressed in the same case — emitting both
	// yields "multiple primary keys for table" (42P16).
	suppressInlinePK := pkLine != ""

	var b strings.Builder
	fmt.Fprintf(&b, "CREATE TABLE %s.%s (\n",
		pg.QuoteIdentifier(schema), pg.QuoteIdentifier(t.Name))
	for i, c := range t.Columns {
		fmt.Fprintf(&b, "    %s", renderColumnDefEx(c, suppressInlinePK))
		if i < len(t.Columns)-1 || pkLine != "" {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(pkLine)
	b.WriteString(")")
	return b.String()
}

// renderPKLine returns the table-level PRIMARY KEY clause for t,
// including its trailing newline, or "" when the primary key is carried
// by the inline column shorthand or the table has none.
//
// The table-level form is required whenever the shorthand cannot express
// the intent:
//
//   - the PK spans several columns — two inline marks are 42P16, not a
//     composite key, so the inline marks are synthesised into one clause
//     rather than silently dropping the PK;
//   - the PK column carries no inline mark, so there is nothing to hang
//     the shorthand on;
//   - the constraint is named, and the shorthand has nowhere to put a
//     name.
func renderPKLine(t keystonev1alpha1.DesiredTable) string {
	cols := t.PrimaryKey
	if len(cols) == 0 {
		for _, c := range t.Columns {
			if c.PrimaryKey {
				cols = append(cols, c.Name)
			}
		}
	}
	if len(cols) == 0 {
		return ""
	}
	// Single column already marked inline, unnamed: the shorthand is the
	// canonical spelling, so keep it.
	if t.PrimaryKeyName == "" && len(cols) == 1 && isInlinePK(t, cols[0]) {
		return ""
	}
	if t.PrimaryKeyName != "" {
		return fmt.Sprintf("    CONSTRAINT %s PRIMARY KEY (%s)\n",
			pg.QuoteIdentifier(t.PrimaryKeyName), quoteList(cols))
	}
	return fmt.Sprintf("    PRIMARY KEY (%s)\n", quoteList(cols))
}

// isInlinePK reports whether the named column carries PrimaryKey:true.
func isInlinePK(t keystonev1alpha1.DesiredTable, name string) bool {
	for _, c := range t.Columns {
		if c.Name == name && c.PrimaryKey {
			return true
		}
	}
	return false
}

// renderColumnDef preserves the original inline-PK-emitting signature
// for callers that don't have table-level context (e.g. ALTER TABLE
// ADD COLUMN paths in diffTableFull).
func renderColumnDef(c keystonev1alpha1.DesiredColumn) string {
	return renderColumnDefEx(c, false)
}

// renderColumnDefEx is the context-aware version. suppressInlinePK
// turns off the inline `PRIMARY KEY` even when c.PrimaryKey=true —
// used by renderCreateTable when a composite/multi-PK is being
// emitted at table level.
func renderColumnDefEx(c keystonev1alpha1.DesiredColumn, suppressInlinePK bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", pg.QuoteIdentifier(c.Name), string(c.Type))

	// GENERATED ... STORED goes immediately after the type, matching pg_dump.
	// It is mutually exclusive with DEFAULT: PostgreSQL rejects a column that
	// declares both, and the generation expression is the column's only source
	// of value.
	if c.Generated != "" {
		fmt.Fprintf(&b, " GENERATED ALWAYS AS (%s) STORED", c.Generated)
	}
	if !c.Nullable {
		b.WriteString(" NOT NULL")
	}
	if c.Default != "" && c.Generated == "" {
		fmt.Fprintf(&b, " DEFAULT %s", c.Default)
	}
	// Identity before PRIMARY KEY: PostgreSQL accepts either order, but this
	// matches the ordering pg_dump emits, which keeps hand-diffing sane.
	switch c.Identity {
	case "ALWAYS":
		b.WriteString(" GENERATED ALWAYS AS IDENTITY")
	case "BY DEFAULT":
		b.WriteString(" GENERATED BY DEFAULT AS IDENTITY")
	}
	if c.PrimaryKey && !suppressInlinePK {
		b.WriteString(" PRIMARY KEY")
	}
	return b.String()
}

func renderCreateIndex(schema, table string, idx keystonev1alpha1.DesiredIndex) string {
	return renderIndexDDL(schema, table, idx, false)
}

func renderCreateIndexConcurrently(schema, table string, idx keystonev1alpha1.DesiredIndex) string {
	return renderIndexDDL(schema, table, idx, true)
}

// renderIndexDDL emits a CREATE INDEX statement covering all four
// keystone#4 features: per-column sort direction, expression indexes,
// covering INCLUDE, and per-column opclass — alongside the existing
// partial-index WHERE predicate. Three input shapes are supported on
// DesiredIndex:
//
//  1. Columns []string                — simple form, one btree col
//     per entry, ASC default
//  2. ColumnRefs []DesiredIndexColumn — rich form, per-column DESC/
//     NULLS/opclass
//  3. Expression string                — expression body, e.g.
//     "lower(email)"
//
// Exactly one of Columns / ColumnRefs / Expression must be populated;
// the renderer prefers them in declared order.
func renderIndexDDL(schema, table string, idx keystonev1alpha1.DesiredIndex, concurrent bool) string {
	var b strings.Builder
	b.WriteString("CREATE ")
	if idx.Unique {
		b.WriteString("UNIQUE ")
	}
	if concurrent {
		fmt.Fprintf(&b, "INDEX CONCURRENTLY IF NOT EXISTS %s ON %s.%s",
			pg.QuoteIdentifier(idx.Name),
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(table))
	} else {
		fmt.Fprintf(&b, "INDEX %s ON %s.%s",
			pg.QuoteIdentifier(idx.Name),
			pg.QuoteIdentifier(schema), pg.QuoteIdentifier(table))
	}

	method := idx.Method
	if method == "" {
		method = "btree"
	}
	fmt.Fprintf(&b, " USING %s (%s)", method, renderIndexColumnList(idx))

	// Covering / INCLUDE clause (btree only at PG-level; we emit
	// regardless because PG itself rejects non-btree + INCLUDE so the
	// error surface is correct without us pre-validating.)
	if len(idx.Include) > 0 {
		fmt.Fprintf(&b, " INCLUDE (%s)", quoteList(idx.Include))
	}

	// NULLS NOT DISTINCT (PG 15+, only meaningful with UNIQUE) — placed
	// AFTER the column list / INCLUDE per PG syntax and BEFORE the WHERE
	// predicate.
	if idx.Unique && idx.NullsNotDistinct {
		b.WriteString(" NULLS NOT DISTINCT")
	}

	if idx.Where != "" {
		fmt.Fprintf(&b, " WHERE %s", idx.Where)
	}
	return b.String()
}

// renderIndexColumnList emits the parenthesised body for the index's
// USING <method> (...) clause. Three branches mirror the spec shapes.
func renderIndexColumnList(idx keystonev1alpha1.DesiredIndex) string {
	switch {
	case idx.Expression != "":
		// Wrap in parens — this is the inner content, the outer
		// (...) is added by the calling fmt.Fprintf above.
		return "(" + idx.Expression + ")"
	case len(idx.ColumnRefs) > 0:
		parts := make([]string, 0, len(idx.ColumnRefs))
		for _, c := range idx.ColumnRefs {
			parts = append(parts, renderIndexColumn(c))
		}
		return strings.Join(parts, ", ")
	case len(idx.Columns) > 0:
		return quoteList(idx.Columns)
	default:
		// CRD validation should prevent this. Defensive: emit nothing
		// so the resulting DDL is obviously malformed and PG rejects
		// rather than silently creating a zero-column index.
		return ""
	}
}

// renderIndexColumn renders a single ColumnRefs entry. Either Name
// (column ref) OR Expression (per-column SQL expression) is set;
// CRD webhook enforces the mutual exclusivity. opclass / direction /
// nulls are common to both.
func renderIndexColumn(c keystonev1alpha1.DesiredIndexColumn) string {
	var b strings.Builder
	switch {
	case c.Expression != "":
		// Per-column expression — wrap in parens so PG parses
		// `(coalesce(col, ''))` correctly even when other entries in
		// the column list are bare column references.
		fmt.Fprintf(&b, "(%s)", c.Expression)
	default:
		b.WriteString(pg.QuoteIdentifier(c.Name))
	}
	if c.OpClass != "" {
		// PG identifier rules: opclass names follow the same identifier
		// rules as table/column names. QuoteIdentifier handles the
		// edge cases.
		fmt.Fprintf(&b, " %s", pg.QuoteIdentifier(c.OpClass))
	}
	switch strings.ToLower(c.Direction) {
	case "desc":
		b.WriteString(" DESC")
	case "asc", "":
		// PG default. Emit explicitly only for desc.
	}
	switch strings.ToLower(c.Nulls) {
	case "first":
		b.WriteString(" NULLS FIRST")
	case "last":
		b.WriteString(" NULLS LAST")
	}
	return b.String()
}

func needsPKLine(t keystonev1alpha1.DesiredTable) bool {
	if len(t.PrimaryKey) == 0 {
		return false
	}
	if len(t.PrimaryKey) == 1 {
		for _, c := range t.Columns {
			if c.Name == t.PrimaryKey[0] && c.PrimaryKey {
				return false
			}
		}
	}
	return true
}

func quoteList(names []string) string {
	q := make([]string, 0, len(names))
	for _, n := range names {
		q = append(q, pg.QuoteIdentifier(n))
	}
	return strings.Join(q, ", ")
}

func indexDDLMatch(observed, rendered string) bool {
	return normaliseDDL(observed) == normaliseDDL(rendered)
}

// normaliseDDL puts an index DDL string into a canonical form that
// strips cosmetic differences between what PostgreSQL emits via
// pg_get_indexdef (which omits identifier quotes when the identifier
// is a valid bare PG identifier) and what our renderer emits (which
// always quotes via pg.QuoteIdentifier).
//
// Without this normalisation, identical indexes look diff'd to the
// SchemaDefinitionReconciler — observed in example-service 2026-05-03:
// 1015 declared indexes ALL flagged as drift (CREATE+DROP) because
// the comparison saw `"idx_arc_status"` (rendered, quoted) vs
// `idx_arc_status` (observed, unquoted). Both refer to the same
// object; the differ should treat them as equal.
//
// We strip an identifier-quote ONLY when the unquoted form is itself
// a valid bare PG identifier (lowercase, starts with letter or
// underscore, contains only [a-z0-9_]). For mixed-case or special-
// character identifiers PG MUST quote in both observed and rendered,
// so equality stays correct without our help.
func normaliseDDL(s string) string {
	s = strings.ToLower(s)
	s = stripBareIdentifierQuotes(s)
	s = strings.Join(strings.Fields(s), " ")
	// Idempotency / parallel-creation keywords PG strips on readback.
	// CREATE INDEX CONCURRENTLY IF NOT EXISTS is parser-time only; the
	// stored index has no record of either keyword, so pg_get_indexdef
	// returns plain CREATE INDEX. Strip both for equality.
	s = strings.ReplaceAll(s, "create index concurrently ", "create index ")
	s = strings.ReplaceAll(s, "create unique index concurrently ", "create unique index ")
	s = strings.ReplaceAll(s, " if not exists ", " ")
	// `ON ONLY <table>` and `ON <table>` are equivalent for an existing
	// partitioned-parent index whose partitions already have child
	// indexes — both refer to the same logical index. PG returns
	// `ON ONLY` from pg_get_indexdef on partitioned parents; our
	// renderer omits ONLY. Treat them as equivalent.
	s = strings.ReplaceAll(s, " on only ", " on ")
	// Outer parens around a single function-call expression in an
	// index column list. PG omits them in pg_get_indexdef
	// (`btree (..., coalesce(rule_value, ''::text), ...)`); our
	// renderer wraps DesiredIndexColumn.Expression values in parens
	// (`btree (..., (coalesce(...)), ...)`). Strip a single layer of
	// outer-only parens around any function-call argument.
	s = stripRedundantExpressionParens(s)
	s = normaliseArrayCasts(s)
	// `x IN (a, b)` is rewritten by PG to `x = ANY (ARRAY[a, b])` at
	// parse time, so pg_get_indexdef / pg_get_constraintdef always emit
	// the ANY-form while a hand-authored predicate uses IN. Collapse the
	// ANY-form back to IN before the cast/paren passes so the two
	// compare equal. Runs after normaliseArrayCasts has stripped the
	// `(array[...])::t[]` cast wrapper down to a bare `array[...]`.
	s = normaliseInAnyArray(s)
	s = stripVarcharTextCastEquality(s)
	s = normaliseWhereClauseCanonical(s)
	return s
}

// normaliseInAnyArray rewrites PG's canonical membership form
//
//	<lhs> = any (array[items])      // and the paren-less variant:
//	<lhs> = any array[items]
//
// to the authored form `<lhs> in (items)`. PG rewrites every
// `IN (constant-list)` predicate to `= ANY (ARRAY[...])` at parse time,
// so a partial-index WHERE / CHECK predicate authored as
// `status IN ('pending','failed')` is stored — and read back via
// pg_get_indexdef — as `(status)::text = ANY (ARRAY['pending'::…])`.
// The two are semantically identical for a literal array, so collapsing
// the ANY-form to the IN-form lets the authored and stored predicates
// compare equal and stops the differ emitting a perpetual
// DROP+CREATE INDEX (observed 2026-06-14 on
// marketing.ix_outbox_events_status_next_retry_at).
//
// Operates on the lowercased, whitespace-collapsed string and preserves
// single-quoted literals verbatim. The remaining per-literal casts
// inside `items` (`'pending'::character varying`) are stripped by the
// literal-cast pass in normaliseWhereClauseCanonical.
func normaliseInAnyArray(s string) string {
	const marker = "= any "
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// Preserve quoted regions verbatim.
		if s[i] == '\'' {
			b.WriteByte(s[i])
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}
		if strings.HasPrefix(s[i:], marker) {
			j := i + len(marker)
			hadParen := false
			if j < len(s) && s[j] == '(' {
				hadParen = true
				j++
			}
			if strings.HasPrefix(s[j:], "array[") {
				bracketOpen := j + len("array") // index of '['
				bracketClose := matchBracket(s, bracketOpen)
				if bracketClose > 0 {
					after := bracketClose + 1
					ok := true
					if hadParen {
						if after < len(s) && s[after] == ')' {
							after++
						} else {
							ok = false // unbalanced — leave untouched
						}
					}
					if ok {
						items := s[bracketOpen+1 : bracketClose]
						b.WriteString("in (")
						b.WriteString(items)
						b.WriteString(")")
						i = after
						continue
					}
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// normaliseWhereClauseCanonical reduces the WHERE-clause body of a
// CREATE INDEX statement to a paren-stripped, cast-stripped, boolean-
// canonicalised form so YAML-authored and pg_get_indexdef-rendered
// predicates compare equal even when PG has rewritten them.
//
// Three independent canonicalisations all PG performs on partial-
// index predicates at storage time:
//
//  1. Outer parens around the WHERE body (always added). YAML
//     authors typically write `WHERE x IS NOT NULL`; PG stores
//     `WHERE (x IS NOT NULL)`.
//
//  2. Inner parens around each comparison in a multi-comparison
//     AND/OR expression. YAML: `WHERE a = 1 AND b = 2`; PG stores
//     `WHERE ((a = 1) AND (b = 2))` (outer + per-comparison).
//
//  3. Trailing `::text` cast on string literals being compared to
//     `varchar` columns. YAML: `WHERE col = 'value'`; PG stores
//     `WHERE ((col)::text = 'value'::text)`. The column-side cast
//     (`(col)::text`) is handled by stripVarcharTextCastEquality
//     above; this function handles the literal-side cast
//     (`'value'::text`) which the equality matcher's strict
//     paren-wrapped requirement doesn't cover.
//
// The implementation scans the lowered-and-collapsed DDL string for
// ` where ` and reduces everything that follows by:
//
//   - Iteratively stripping balanced outer parens until the body is
//     no longer paren-wrapped.
//   - Stripping `::text` from any quoted string literal followed by
//     `::text` (PG only adds this on string-vs-varchar comparisons).
//   - Iteratively stripping all balanced inner parens (PG's per-
//     comparison wrapping). Safe because pg_get_indexdef never uses
//     parens to change operator precedence — only for grouping.
//     After stripping, `AND`/`OR` precedence is implicit and matches
//     the YAML form.
//
// Verified live 2026-05-19 against bundle `workflow-engine-public-
// desired-d5d8ae16f68c`: 8 partial-index DROP+CREATE pairs converge
// to no-op after this normalisation.
//   - `WHERE resume_at IS NOT NULL`        (live: `WHERE (resume_at IS NOT NULL)`)
//   - `WHERE retry_at IS NOT NULL`         (live: `WHERE (retry_at IS NOT NULL)`)
//   - `WHERE webhook_path IS NOT NULL`     (live: `WHERE (webhook_path IS NOT NULL)`)
//   - + 4 more IS-NOT-NULL partial indexes
//   - `WHERE trigger_type = 'schedule' AND is_active = true AND schedule_enabled = true`
//     (live: `WHERE (((trigger_type)::text = 'schedule'::text)
//     AND (is_active = true)
//     AND (schedule_enabled = true))`)
//
// The boolean `= true|false` canonicalisation is NOT applied here
// because pg_get_indexdef PRESERVES the `= true` form when the
// comparison is inside a paren-wrapped AND-clause (verified live).
// Stripping it would over-collapse and produce false equality.
func normaliseWhereClauseCanonical(s string) string {
	idx := strings.Index(s, " where ")
	if idx < 0 {
		return s
	}
	head := s[:idx+len(" where ")]
	body := strings.TrimSpace(s[idx+len(" where "):])

	// (a) Strip outer paren layers — handles `(x IS NOT NULL)` form
	// and the multi-layer `(((x = y) AND ...))` form by iterating.
	for strings.HasPrefix(body, "(") {
		close := matchParen(body, 0)
		if close < 0 || close != len(body)-1 {
			break
		}
		body = strings.TrimSpace(body[1:close])
	}

	// (b) Strip all balanced inner parens that wrap a comparison or
	// other subexpression. PG never uses parens to change operator
	// precedence in pg_get_indexdef output, only for grouping. After
	// this pass `(a = 1) AND (b = 2)` collapses to `a = 1 and b = 2`.
	// Run BEFORE the literal-cast strip so a paren-wrapped double cast
	// left by array-cast distribution (`('x'::character varying)::text`)
	// becomes `'x'::character varying::text` — a bare chain the literal
	// stripper can then remove in full.
	body = stripInnerParens(body)

	// (c) Strip the trailing string-type cast chain from bare string
	// literals (`'x'::text`, `'x'::character varying::text`).
	body = stripTextCastFromLiteral(body)

	// (d) Strip bareword `<ident>::text` column-side casts. PG wraps
	// varchar columns in parens before adding the cast — `(col)::text`.
	// stripVarcharTextCastEquality handles the paren-wrapped form
	// when BOTH sides have it; after stripInnerParens runs, the
	// remaining `<col>::text` (no parens) needs its own pass.
	body = stripBarewordTextCast(body)

	return head + body
}

// stripBarewordTextCast removes `<identifier>::text` patterns where
// the identifier is a bare PG column name (not paren-wrapped). Runs
// after stripInnerParens has unwrapped the `(col)::text` form.
//
// Example: `trigger_type::text = 'schedule'` → `trigger_type = 'schedule'`.
//
// Quoted regions are preserved verbatim.
func stripBarewordTextCast(s string) string {
	const suffix = "::text"
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\'' {
			// Skip quoted region.
			b.WriteByte(c)
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}
		// Look for an identifier-like token followed by ::text.
		if isASCIILetter(c) || c == '_' {
			j := i
			for j < len(s) && (isASCIILetter(s[j]) || (s[j] >= '0' && s[j] <= '9') || s[j] == '_') {
				j++
			}
			ident := s[i:j]
			if strings.HasPrefix(s[j:], suffix) {
				// Found <ident>::text — emit ident, skip cast.
				b.WriteString(ident)
				i = j + len(suffix)
				continue
			}
			b.WriteString(ident)
			i = j
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// stripTextCastFromLiteral walks a string and removes a value-
// preserving string-type cast suffix from any single-quoted literal
// that has it. Quoted regions are skipped verbatim except for the
// trailing cast token.
//
// Example: `col = 'value'::text` → `col = 'value'`,
// `status in ('pending'::character varying)` → `status in ('pending')`.
//
// The recognised casts are the interchangeable string types PG emits
// when it canonicalises a literal against a varchar/text/bpchar
// column: `::text`, `::character varying`, `::varchar`, `::bpchar`.
// All are value-preserving for a string literal, so stripping them for
// equality never changes meaning. Longest tokens are matched first so
// `::character varying` isn't mistaken for a bare `::character`.
//
// Does not touch column-side casts (`(col)::text`); those are
// handled by stripVarcharTextCastEquality.
func stripTextCastFromLiteral(s string) string {
	// Longest-first so `::character varying` wins over any prefix.
	suffixes := []string{"::character varying", "::bpchar", "::varchar", "::text"}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\'' {
			b.WriteByte(s[i])
			i++
			continue
		}
		// Scan to end of single-quoted literal. PG-canonical output
		// never embeds escape sequences inside indexdef literals
		// (PG quotes via repeated single-quote, but indexdef
		// expressions don't typically contain those — keep simple).
		j := i + 1
		for j < len(s) && s[j] != '\'' {
			j++
		}
		if j >= len(s) {
			// Unterminated quote — emit rest verbatim and bail.
			b.WriteString(s[i:])
			return b.String()
		}
		// s[i..j] inclusive is the quoted literal
		b.WriteString(s[i : j+1])
		i = j + 1
		// Strip any chain of trailing string-type casts. PG's array-cast
		// distribution can leave a double cast on a literal once its
		// wrapping parens are removed (`'x'::character varying::text`),
		// so strip repeatedly until none remain.
		for {
			stripped := false
			for _, suffix := range suffixes {
				if strings.HasPrefix(s[i:], suffix) {
					i += len(suffix)
					stripped = true
					break
				}
			}
			if !stripped {
				break
			}
		}
	}
	return b.String()
}

// stripInnerParens iteratively removes all balanced paren pairs that
// wrap a single subexpression — i.e. parens that PG uses purely for
// grouping in pg_get_indexdef output but that the YAML author
// didn't write. The criterion for "removable" is: a `(`-`)` pair
// such that REMOVING THEM doesn't change the token sequence's
// operator precedence semantics.
//
// Implementation: walk the string; for each `(` whose matching `)`
// exists, emit the content without the parens unless the parens are
// the outermost of an operator-changing precedence context (we
// approximate "operator-changing" as zero — PG canonical output never
// uses parens that way, so unconditional strip is safe for this
// input shape).
//
// Quoted string literals are preserved verbatim — parens inside
// quotes are payload.
//
// Example:
//
//	`(a = 1) and (b = 2) and (c is not null)`
//	→ `a = 1 and b = 2 and c is not null`
func stripInnerParens(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\'' {
			// Skip quoted literal.
			b.WriteByte(c)
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}
		if c == '(' {
			closeIdx := matchParen(s, i)
			if closeIdx < 0 {
				// Unbalanced — emit verbatim.
				b.WriteByte(c)
				i++
				continue
			}
			// Recurse on the inner content (so nested parens get
			// stripped too).
			inner := stripInnerParens(s[i+1 : closeIdx])
			b.WriteString(inner)
			i = closeIdx + 1
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// stripVarcharTextCastEquality canonicalises the PostgreSQL rewrite of
// `<varchar_col> = <varchar_literal>` (and the reverse) into
// `(<varchar_col>)::text = (<varchar_literal>)::text`. PG's parser
// rewrites comparisons involving `character varying` operands by
// adding a `::text` cast to BOTH sides; the rewritten form is what
// pg_get_indexdef emits, so a SchemaDefinition's partial-index WHERE
// authored in the natural form `(status = 'active'::character varying)`
// disagrees with live `((status)::text = ('active'::character varying)::text)`
// on every reconcile — exact-string-equality based comparison fails
// and the differ emits a DROP/CREATE pair that PG re-stores in the
// cast-distributed form, looping forever.
//
// Verified live 2026-05-19 on
// `idx_iam_users_pending_deletion` (example-service-public-desired):
//
//	YAML where:  (activation_status = 'pending_deletion'::character varying)
//	pg_get_indexdef:
//	             ((activation_status)::text = ('pending_deletion'::character varying)::text)
//
// Same loop signature as normaliseArrayCasts.
//
// # What it transforms
//
// Strips a `::text` cast from both sides of a `=` token when the
// pattern is `<paren-wrapped expression>::text = <paren-wrapped
// expression>::text`. After stripping, the two sides converge to
// the natural form PG accepted on apply.
//
// Strict on shape:
//
//   - `=` must be the comparison operator (other operators like
//     `<>`, `<`, `>`, `>=`, `<=` follow the same canonicalisation —
//     handled by the same function via the operator-token check).
//   - Both sides MUST be `(...)::text` form. Half-cast forms don't
//     appear in PG canonicalised output and are left alone.
//   - The outer paren level inside each side must be balanced; the
//     scanner matches parens so nested casts are handled.
//
// # What it does NOT touch
//
//   - Single-quoted literals (`'foo::text = bar'`) — quoted text is
//     skipped verbatim.
//   - Comparisons against numeric/boolean (no `::text` cast applied
//     by PG for those types).
//   - Cast variants other than `::text` (`::int`, `::uuid`, etc.) —
//     those don't appear in PG's varchar-equality rewrite. If similar
//     loops appear on other types later, extend the cast-tail matcher.
func stripVarcharTextCastEquality(s string) string {
	// Operators PG rewrites with the cast-distribution form for
	// varchar operands. We scan for any of these tokens; the
	// rewriter handles each identically (cast-strip both sides).
	ops := []string{" = ", " <> ", " >= ", " <= ", " < ", " > "}
	out := s
	for _, op := range ops {
		out = stripTextCastAroundOp(out, op)
	}
	return out
}

// stripTextCastAroundOp finds occurrences of
// `(<balanced>)::text<op>(<balanced>)::text` and rewrites to
// `<inner>=<inner>`. The op argument carries its surrounding
// whitespace so we only match between fully-tokenised operators.
func stripTextCastAroundOp(s, op string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// Skip quoted literals — operators inside quotes are payload.
		if s[i] == '\'' {
			b.WriteByte(s[i])
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}
		idx := strings.Index(s[i:], op)
		if idx < 0 {
			b.WriteString(s[i:])
			break
		}
		opStart := i + idx
		// Scan backwards from opStart for `)::text` immediately
		// preceding (allow leading whitespace already consumed by op
		// prefix).
		lhsEnd := opStart
		lhs, lhsStart, lhsOK := scanBackTextCast(s, lhsEnd)
		// Scan forwards from opStart+len(op) for `(`<balanced>`)::text`.
		rhsStart := opStart + len(op)
		rhs, rhsEnd, rhsOK := scanFwdTextCast(s, rhsStart)
		if !lhsOK || !rhsOK {
			// Not a varchar-cast equality — emit unchanged up to and
			// including the operator, then continue past it.
			b.WriteString(s[i : opStart+len(op)])
			i = opStart + len(op)
			continue
		}
		// Emit up to lhsStart, then inner forms joined by op, skip
		// to rhsEnd.
		b.WriteString(s[i:lhsStart])
		b.WriteString(lhs)
		b.WriteString(op)
		b.WriteString(rhs)
		i = rhsEnd
	}
	return b.String()
}

// scanBackTextCast looks at s[..end] and returns the inner expression
// of a trailing `(...)::text` pattern (without surrounding parens or
// `::text`), plus the index where the pattern starts, plus ok.
func scanBackTextCast(s string, end int) (string, int, bool) {
	const suffix = ")::text"
	if end < len(suffix) || s[end-len(suffix):end] != suffix {
		return "", 0, false
	}
	parenClose := end - len("::text") - 1 // position of `)`
	parenOpen := matchBracketBack(s, parenClose, '(', ')')
	if parenOpen < 0 {
		return "", 0, false
	}
	return s[parenOpen+1 : parenClose], parenOpen, true
}

// scanFwdTextCast looks at s[start..] and returns the inner
// expression of a leading `(...)::text` pattern (without surrounding
// parens or `::text`), plus the index AFTER the `::text` suffix, plus
// ok.
func scanFwdTextCast(s string, start int) (string, int, bool) {
	if start >= len(s) || s[start] != '(' {
		return "", 0, false
	}
	parenClose := matchParen(s, start)
	if parenClose < 0 {
		return "", 0, false
	}
	const suffix = "::text"
	tailStart := parenClose + 1
	if tailStart+len(suffix) > len(s) || s[tailStart:tailStart+len(suffix)] != suffix {
		return "", 0, false
	}
	return s[start+1 : parenClose], tailStart + len(suffix), true
}

// matchBracketBack walks BACKWARDS from end (which must point at a
// closing bracket of pair (open, close)) and returns the index of the
// matching opening bracket. Returns -1 if no balanced match exists.
// Skips characters inside single-quoted literals.
func matchBracketBack(s string, end int, open, close byte) int {
	if end < 0 || end >= len(s) || s[end] != close {
		return -1
	}
	depth := 1
	i := end - 1
	inQuote := false
	for i >= 0 {
		c := s[i]
		if c == '\'' {
			// Look-back for paired quote. If the character before this
			// one is also `'`, it's an escaped quote in some dialects;
			// PG canonical output doesn't produce escaped quotes inside
			// these expressions so a simple toggle is sufficient.
			inQuote = !inQuote
		} else if !inQuote {
			if c == close {
				depth++
			} else if c == open {
				depth--
				if depth == 0 {
					return i
				}
			}
		}
		i--
	}
	return -1
}

// defaultsEqual reports whether two column-default expressions are
// equivalent under PostgreSQL's storage canonicalisation. PG does NOT
// store the user-supplied default verbatim; common rewrites:
//
//   - Function-call schema prefix: `public.uuid_generate_v4()` is
//     stored as `uuid_generate_v4()` when `public` is in the active
//     search_path (the cluster default). information_schema.columns.
//     column_default returns the stored unqualified form, so YAML
//     that schema-qualifies the function looks drifted forever.
//   - Whitespace + identifier-quote variations: trimmed and lowered
//     before comparing.
//
// Verified live 2026-05-19 on integration-hub-cfg-desired against
// `integration_hub.{categories,providers,tenant_integrations,
// config_audit_log,usage_records}.id` — YAML
// `default: public.uuid_generate_v4()` vs live `uuid_generate_v4()`
// looped 5 ops/reconcile/minute since 2026-05-10.
//
// Returns true on no-drift (no SET DEFAULT emitted), false on
// genuine drift.
func defaultsEqual(desired, observed string) bool {
	return normaliseDefault(desired) == normaliseDefault(observed)
}

// normaliseDefault lowercases + collapses whitespace + strips the
// `public.` schema prefix from function-call references in column
// defaults AND strips PG's `::<type>` cast suffixes from literal
// expressions. We strip ONLY `public.` because it's the cluster's
// default search_path prefix (set in example-pg and example-app-pg
// init). Other schemas (e.g. `keystone.`) genuinely need to remain
// qualified — PG stores them so. If a different default-search-path
// schema appears later, extend the prefix list.
//
// The literal-type-cast strip handles pg_get_expr() canonical output
// adding `::text` / `::character varying` / `::jsonb` / `::integer[]`
// etc. to every literal default. YAML defaults are bare (e.g. `”`,
// `'{}'`); PG stores them cast (e.g. `”::text`, `'{}'::jsonb`).
// Without normalisation, the differ emits an ALTER COLUMN SET DEFAULT
// on every reconcile that PG applies as a no-op rewrite — silent
// no-converge loop. Verified live 2026-05-20 on master-data-,
// notification-service-, storage-api-storage-public-desired (12 ops
// across 3 SDs).
func normaliseDefault(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Join(strings.Fields(s), " ")
	// Strip `::<type>[]?` casts that PG attaches to literal defaults
	// (text, character varying, jsonb, integer[], text[], etc.).
	s = stripLiteralTypeCasts(s)
	// Strip a `public.` immediately preceding a bareword identifier.
	// Bareword identifier check prevents accidental stripping of
	// quoted "public.something" forms (rare; deliberately preserved).
	s = stripPublicSchemaPrefix(s)
	return s
}

// stripLiteralTypeCasts strips PG `::<type>` cast suffixes from
// literal expressions in default-value strings. PG's pg_get_expr()
// canonicalises every default through its parser, attaching a type
// cast to every literal even when the YAML author wrote it bare:
//
//	user wrote     PG stored
//	──────────────────────────
//	''             ''::text
//	'synced'       'synced'::character varying
//	'{}'           '{}'::jsonb
//	'{}'           '{}'::integer[]
//	'{}'           '{}'::text[]
//	0              0::integer
//	1.5            1.5::numeric
//
// The differ compares YAML defaults (no casts) against pg_get_expr
// output (always cast). Without normalisation, every reconcile emits
// SET DEFAULT that PG applies as a no-op rewrite — silent no-converge
// loop, identical symptom to the partial-index WHERE-clause bug that
// `stripVarcharTextCastEquality` addresses.
//
// Quoted literals are scanned byte-by-byte and emitted verbatim
// (including any `'...'::cast'` text the user may have embedded
// inside a quote — that text is payload, not syntax). After a
// closing single-quote OR a numeric-literal run, an optional
// `::<ident>[ <ident>]?[]` cast is consumed and dropped.
func stripLiteralTypeCasts(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		// Single-quoted literal — copy verbatim through the closing
		// quote (handling '' as an embedded single-quote escape).
		if c == '\'' {
			b.WriteByte(c)
			i++
			for i < len(s) {
				if s[i] == '\'' {
					// PG embeds a literal `'` as `''` inside a quoted
					// string. Detect and pass through both bytes
					// without terminating the literal.
					if i+1 < len(s) && s[i+1] == '\'' {
						b.WriteByte(s[i])
						b.WriteByte(s[i+1])
						i += 2
						continue
					}
					b.WriteByte(s[i])
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			i = skipTypeCast(s, i)
			continue
		}
		// Bareword numeric literal — emit the run of digits/dot,
		// then strip any trailing ::cast.
		if isDigit(c) {
			for i < len(s) && (isDigit(s[i]) || s[i] == '.') {
				b.WriteByte(s[i])
				i++
			}
			i = skipTypeCast(s, i)
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// skipTypeCast returns the position past a `::<type>` sequence
// starting at position i, or i unchanged when no cast is present.
//
// Recognised forms (all observed live in pg_get_expr output):
//
//	::ident                e.g. ::text, ::jsonb, ::numeric
//	::ident ident          e.g. ::character varying, ::double precision
//	::ident[]              e.g. ::text[], ::integer[]
//	::ident ident[]        rare but valid
//
// Cast identifiers consist of ASCII letters, digits, and underscores.
// Multi-word types are joined by a single space. Trailing `[]`
// indicates an array.
func skipTypeCast(s string, i int) int {
	if i+1 >= len(s) || s[i] != ':' || s[i+1] != ':' {
		return i
	}
	j := i + 2
	if j >= len(s) || !isASCIILetter(s[j]) {
		return i
	}
	// First identifier.
	for j < len(s) && (isASCIILetter(s[j]) || isDigit(s[j]) || s[j] == '_') {
		j++
	}
	// Optional second identifier (multi-word types).
	if j < len(s) && s[j] == ' ' && j+1 < len(s) && isASCIILetter(s[j+1]) {
		j++
		for j < len(s) && (isASCIILetter(s[j]) || isDigit(s[j]) || s[j] == '_') {
			j++
		}
	}
	// Optional [] suffix for array types.
	if j+1 < len(s) && s[j] == '[' && s[j+1] == ']' {
		j += 2
	}
	return j
}

// isDigit reports whether b is an ASCII decimal digit. Local helper
// to keep stripLiteralTypeCasts allocation-free.
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// stripPublicSchemaPrefix removes `public.<ident>` → `<ident>` where
// <ident> is a bare PG identifier (starts with letter/underscore,
// continues with [a-z0-9_]). Single-quoted literals are passed through
// verbatim so a default that legitimately contains the string
// `public.x` inside a quote (e.g. SQL embedded in a function call) is
// not corrupted.
func stripPublicSchemaPrefix(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// Skip single-quoted literals verbatim.
		if s[i] == '\'' {
			b.WriteByte(s[i])
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}
		if strings.HasPrefix(s[i:], "public.") {
			// Confirm what follows is a bareword identifier start.
			rest := s[i+len("public."):]
			if len(rest) > 0 && (isASCIILetter(rest[0]) || rest[0] == '_') {
				// Skip the `public.` prefix — emit just the identifier.
				i += len("public.")
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// normaliseArrayCasts canonicalises PostgreSQL array literal cast
// distribution, converting the outer-cast form
// `(ARRAY[a, b, c])::T[]` into the per-element form
// `ARRAY[(a)::T, (b)::T, (c)::T]` that pg_get_indexdef always emits.
//
// # Why this exists
//
// PostgreSQL accepts both forms in CREATE INDEX SQL but always
// re-renders partial-index WHERE predicates in the per-element form
// when read back via pg_get_indexdef:
//
//	-- author writes (outer-cast form, what most humans type):
//	WHERE (level)::text = ANY ((ARRAY['high'::character varying,
//	                                  'critical'::character varying])::text[])
//	-- pg_get_indexdef returns (per-element form):
//	WHERE (level)::text = ANY (ARRAY[('high'::character varying)::text,
//	                                 ('critical'::character varying)::text])
//
// Both produce the same `text[]` value `{'high','critical'}` and
// PG's planner sees them as identical, but textually they diverge.
//
// Without this normalisation, a SchemaDefinition's partial-index
// WHERE clause authored in the outer-cast form disagrees with the
// observed indexdef on every reconcile, the differ emits a
// DROP/CREATE pair, the runner applies it, PG re-stores the index
// in per-element form, and the next reconcile re-emits the same
// pair — a silent loop that drives runaway MigrationBundle
// re-emission and AuditEntry growth (observed 2026-05-06 against
// idx_iam_login_risk_events_high_risk on example_realm_platform,
// blowing keystone-operator into OOM-loop and pushing etcd into
// EtcdTooManyRequestsAlarm via 230 MB single-batch ranges).
//
// # What it transforms
//
// Input pattern (already lowercased + collapsed by the time it
// reaches this function):
//
//	(array[<comma-separated items>])::<type>[]
//
// Output:
//
//	array[(<item1>)::<type>, (<item2>)::<type>, ...]
//
// The trailing `[]` after `<type>` is consumed (the per-element
// form casts to the scalar type, not the array type).
//
// # What it does NOT touch
//
//   - Already per-element-cast arrays (`array[(x)::t, (y)::t]`) — the
//     leading `(array[` pattern doesn't match without a wrapping paren.
//   - Single-quoted literals (`'array[1, 2]'`) — quoted text is skipped.
//   - Arrays without a trailing `::TYPE[]` cast — only the cast-
//     distribution form is rewritten.
//   - Multi-dimensional arrays (`(array[array[1,2]])::int[][]`) — the
//     simple type-suffix matcher accepts only one trailing `[]`. Not
//     observed in the wild on Keystone-managed schemas; if it appears,
//     extend the type-tail scanner.
//
// Both branches of the differ comparison (rendered desired and
// observed live indexdef) flow through normaliseDDL, so the
// canonicalisation makes them converge regardless of which form
// the SD author wrote.
func normaliseArrayCasts(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		// Skip single-quoted literals verbatim — array contents may
		// contain literal commas/parens that would confuse the scanner.
		if c == '\'' {
			b.WriteByte(c)
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}
		// Look for `(array[`. The outer `(` plus the literal `array[`
		// is the unambiguous marker for the cast-distribution form;
		// per-element form starts with `array[(` and is left alone.
		if c == '(' && strings.HasPrefix(s[i:], "(array[") {
			bracketOpen := i + len("(array[") - 1 // position of `[`
			bracketClose := matchBracket(s, bracketOpen)
			if bracketClose < 0 || bracketClose+1 >= len(s) || s[bracketClose+1] != ')' {
				b.WriteByte(c)
				i++
				continue
			}
			outerClose := bracketClose + 1 // position of `)`
			// Require `::<TYPE>[]` immediately after.
			tail := s[outerClose+1:]
			if !strings.HasPrefix(tail, "::") {
				b.WriteByte(c)
				i++
				continue
			}
			typeStart := outerClose + 1 + 2 // skip `::`
			typeEnd := typeStart
			// Type identifier may include spaces (e.g. `character varying`)
			// so we accept lower letters, digits, underscores, and spaces.
			for typeEnd < len(s) {
				ch := s[typeEnd]
				if isBareLowerIdentInner(ch) || ch == ' ' {
					typeEnd++
					continue
				}
				break
			}
			// Trim trailing whitespace from the type identifier.
			for typeEnd > typeStart && s[typeEnd-1] == ' ' {
				typeEnd--
			}
			// Require trailing `[]`.
			if typeEnd >= len(s)-1 || s[typeEnd] != '[' || s[typeEnd+1] != ']' {
				b.WriteByte(c)
				i++
				continue
			}
			castType := s[typeStart:typeEnd]
			contents := s[bracketOpen+1 : bracketClose]
			items := splitTopLevelArrayItems(contents)
			b.WriteString("array[")
			for j, item := range items {
				if j > 0 {
					b.WriteString(", ")
				}
				item = strings.TrimSpace(item)
				b.WriteByte('(')
				b.WriteString(item)
				b.WriteString(")::")
				b.WriteString(castType)
			}
			b.WriteByte(']')
			i = typeEnd + 2 // skip past `[]`
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// matchBracket returns the index of the `]` matching the `[` at
// start. Returns -1 if unbalanced. Mirrors matchParen for square
// brackets — quoted-literal aware so contents like `[1,'a]b',2]`
// don't confuse the depth tracker.
func matchBracket(s string, start int) int {
	if start >= len(s) || s[start] != '[' {
		return -1
	}
	depth := 1
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		if c == '\'' {
			i++
			for i < len(s) && s[i] != '\'' {
				i++
			}
			continue
		}
		if c == '[' {
			depth++
		} else if c == ']' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitTopLevelArrayItems splits an array literal's contents on
// top-level commas, respecting parens, brackets, and single-quoted
// literals. Differs from splitTopLevelCommas (in keystonectl) by
// also tracking bracket depth — array elements may themselves be
// array literals.
func splitTopLevelArrayItems(s string) []string {
	var out []string
	parenDepth, brackDepth := 0, 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			// Skip quoted literal.
			i++
			for i < len(s) && s[i] != '\'' {
				i++
			}
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			brackDepth++
		case ']':
			if brackDepth > 0 {
				brackDepth--
			}
		case ',':
			if parenDepth == 0 && brackDepth == 0 {
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

// stripRedundantExpressionParens removes a single outer paren layer
// around function-call expressions inside an index column list.
// Targets the `(<funcname>(<args>))` pattern only when it appears as a
// list element — i.e., the outer `(` is preceded (skipping whitespace)
// by either `,` (subsequent column) or another `(` (first column of
// the index column list).
//
// PG's pg_get_indexdef emits function-call columns without the extra
// wrapping paren (`btree (a, coalesce(x, y), b)`); our renderer wraps
// any DesiredIndexColumn.Expression in parens
// (`btree (a, (coalesce(x, y)), b)`). This stripper closes that gap
// without disturbing predicate parens (`WHERE (status = 'x')`) or
// arithmetic-precedence parens (`(a + b)`).
func stripRedundantExpressionParens(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		// Track single-quoted literals (already-lowercased) — preserve
		// them verbatim so quoted text doesn't trigger the stripper.
		if c == '\'' {
			b.WriteByte(c)
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}
		// Only consider `(funcname(...))` when its outer `(` is in a
		// list-element position: previous non-space byte is `,` or `(`.
		if c == '(' && i+1 < len(s) && isBareLowerIdentChar(s[i+1]) && isListElementStart(s, i) {
			// Scan funcname.
			j := i + 1
			for j < len(s) && isBareLowerIdentInner(s[j]) {
				j++
			}
			// Optional whitespace before the function-call open paren.
			k := j
			for k < len(s) && s[k] == ' ' {
				k++
			}
			if k < len(s) && s[k] == '(' {
				// We have `(funcname(...)` — find matching close of the
				// inner call.
				closing := matchParen(s, k)
				if closing > 0 && closing+1 < len(s) && s[closing+1] == ')' {
					// Outer paren is redundant — drop it.
					b.WriteString(s[i+1 : closing+1]) // funcname(...)
					i = closing + 2                   // skip past outer ')'
					continue
				}
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// isListElementStart returns true when the byte before position i is
// either a comma or an open paren (skipping whitespace) — meaning
// position i is the start of a fresh list element. Returns false at
// the start of the string.
func isListElementStart(s string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		c := s[j]
		if c == ' ' || c == '\t' || c == '\n' {
			continue
		}
		return c == ',' || c == '('
	}
	return false
}

// matchParen returns the index of the `)` matching the `(` at start.
// Returns -1 if unbalanced. Respects single-quoted literals.
func matchParen(s string, start int) int {
	if start >= len(s) || s[start] != '(' {
		return -1
	}
	depth := 1
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		if c == '\'' {
			i++
			for i < len(s) && s[i] != '\'' {
				i++
			}
			continue
		}
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isBareLowerIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || c == '_'
}

func isBareLowerIdentInner(c byte) bool {
	return isBareLowerIdentChar(c) || (c >= '0' && c <= '9')
}

// stripBareIdentifierQuotes removes double-quote pairs around bare
// PG identifiers. A bare identifier is [a-z_][a-z0-9_]*. Quoted
// strings that aren't bare identifiers (mixed-case, contain dashes,
// reserved words, etc.) are LEFT QUOTED — PG also quotes them in
// pg_get_indexdef output, so equality holds.
//
// The walk respects single-quote string literals so we don't strip
// quotes inside e.g. WHERE 'high' :: text predicates.
func stripBareIdentifierQuotes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inSingle := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' {
			inSingle = !inSingle
			b.WriteByte(c)
			continue
		}
		if c == '"' && !inSingle {
			// Find matching closing quote (same scan rules — no escapes
			// inside double-quoted identifiers per PG).
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				// Unbalanced quote — emit as-is and bail.
				b.WriteString(s[i:])
				return b.String()
			}
			ident := s[i+1 : i+1+end]
			if isBareLowerIdentifier(ident) {
				b.WriteString(ident)
			} else {
				b.WriteByte('"')
				b.WriteString(ident)
				b.WriteByte('"')
			}
			i = i + 1 + end // skip past closing quote
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isBareLowerIdentifier(s string) bool {
	if s == "" {
		return false
	}
	first := s[0]
	if !(first >= 'a' && first <= 'z') && first != '_' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// --- Index/lookup helpers ---

func indexDesiredByName(in []keystonev1alpha1.DesiredIndex) map[string]keystonev1alpha1.DesiredIndex {
	m := make(map[string]keystonev1alpha1.DesiredIndex, len(in))
	for _, i := range in {
		m[i.Name] = i
	}
	return m
}

func observedTables(s *drift.Snapshot) map[string]drift.TableShape {
	m := make(map[string]drift.TableShape, len(s.Tables))
	for _, t := range s.Tables {
		if t.Kind == "BASE TABLE" {
			m[t.Name] = t
		}
	}
	return m
}

func desiredTables(s *keystonev1alpha1.SchemaDefinitionSpec) map[string]keystonev1alpha1.DesiredTable {
	m := make(map[string]keystonev1alpha1.DesiredTable, len(s.Tables))
	for _, t := range s.Tables {
		m[t.Name] = t
	}
	return m
}

func observedIndexesByTable(s *drift.Snapshot) map[string][]drift.ObjectDDL {
	m := make(map[string][]drift.ObjectDDL)
	for _, idx := range s.Indexes {
		m[idx.Table] = append(m[idx.Table], idx)
	}
	return m
}

func observedConstraintsByTable(s *drift.Snapshot) map[string][]drift.ObjectDDL {
	m := make(map[string][]drift.ObjectDDL)
	for _, c := range s.Constraints {
		m[c.Table] = append(m[c.Table], c)
	}
	return m
}

func indexObservedColumns(in []drift.ColumnShape) map[string]drift.ColumnShape {
	m := make(map[string]drift.ColumnShape, len(in))
	for _, c := range in {
		m[c.Name] = c
	}
	return m
}

func indexDesiredColumns(in []keystonev1alpha1.DesiredColumn) map[string]keystonev1alpha1.DesiredColumn {
	m := make(map[string]keystonev1alpha1.DesiredColumn, len(in))
	for _, c := range in {
		m[c.Name] = c
	}
	return m
}

func sortedObservedNames(m map[string]drift.TableShape) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

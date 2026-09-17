// SPDX-License-Identifier: AGPL-3.0-or-later

// Package analyze is Keystone's native lint analyzer framework (Phase 11).
//
// Why in-process vs subprocess: Keystone's MigrationBundle reconciler
// runs the plan phase as part of normal reconcile. Shelling out to
// squawk adds latency + requires the binary in the distroless image.
// Native analyzers run in ~milliseconds and populate
// MigrationPlan.status.findings directly.
//
// Each analyzer implements the Analyzer interface; the Registry runs
// every registered analyzer against a Migration and aggregates
// Findings. Analyzers are expected to be cheap + stateless.
//
// Coverage target evolved: 20 analyzers in Phase 11.2+11.3, 1 cross-
// migration analyzer in Phase A4, and 30 more in Phase A2 (locks,
// compat, DML safety, transaction safety, type conventions, naming).
// The current DefaultRegistry returns 51 analyzers total — see
// docs/roadmap-tier1-gaps.md.
package analyze

import (
	"context"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Migration is what the analyzer framework consumes. It's a lightweight
// view over a MigrationBundle — the reconciler constructs it from the
// bundle spec + resolved source content before invoking Run().
type Migration struct {
	// BundleName + Version identify the source for finding provenance.
	BundleName string
	Version    string

	// Files is the ordered list of SQL files (name + body). Empty when
	// the bundle is operation-based (pgroll-expand-contract).
	Files []FileBody

	// Operations is the ordered list of declarative operations. Empty
	// when the bundle is SQL-based.
	Operations []keystonev1alpha1.MigrationOperation

	// TargetSchema is the schema name the bundle targets (for
	// finding context — "ALTER TABLE in schema X").
	TargetSchema string

	// HasDownSource is true when the MigrationBundle has a downSource
	// configured. Used by the RequireDownMigration analyzer.
	HasDownSource bool

	// Strategy is the MigrationBundle's apply strategy, used by
	// analyzers that only apply to certain strategies.
	Strategy string

	// SchemaObjects is the set of objects (tables, columns, indexes,
	// constraints) currently live in the target schema, populated from
	// drift.Snapshot by the reconciler. Used by cross-bundle breaking
	// change detection to identify objects that other bundles or live
	// applications depend on.
	SchemaObjects *SchemaObjectSet

	// PendingBundleSQL is the SQL content of other MigrationBundles
	// that are Pending or Running against the same target schema.
	// Used by cross-bundle breaking change detection to identify
	// objects referenced by pending bundles that this bundle would
	// break.
	PendingBundleSQL []FileBody
}

// FileBody pairs a filename with its SQL content.
type FileBody struct {
	Name string
	Body string
}

// Finding is one lint observation produced by an analyzer.
type Finding struct {
	// Rule is the analyzer's rule identifier, stable across runs.
	Rule string

	// Severity determines whether admission rejects the bundle.
	Severity keystonev1alpha1.LintLevel

	// File + Line + Column locate the finding in the source. File/Line
	// empty when the finding is bundle-wide (not statement-specific).
	File   string
	Line   int32
	Column int32

	// Message is a human-readable description.
	Message string
}

// Analyzer is a single lint rule.
type Analyzer interface {
	// ID returns the stable rule identifier. Used for CR status
	// dedup and for per-rule exclusion via SchemaPolicy.
	ID() string

	// Description returns a short (<256 char) human explanation.
	Description() string

	// Check runs the rule over the migration and returns findings.
	// MUST be stateless and concurrency-safe.
	Check(ctx context.Context, m *Migration) ([]Finding, error)
}

// Registry is a thread-safe collection of analyzers.
type Registry struct {
	analyzers []Analyzer
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds an analyzer. Duplicate IDs are allowed (no dedup here)
// — callers that care should check before registering.
func (r *Registry) Register(a Analyzer) { r.analyzers = append(r.analyzers, a) }

// RegisterAll is syntactic sugar.
func (r *Registry) RegisterAll(in ...Analyzer) {
	for _, a := range in {
		r.Register(a)
	}
}

// Run invokes every analyzer and returns the aggregated findings.
// Analyzer errors are collected in a single error per-analyzer; Run
// does not short-circuit on failure — we want findings from the
// analyzers that did succeed.
func (r *Registry) Run(ctx context.Context, m *Migration) ([]Finding, error) {
	var findings []Finding
	var firstErr error
	for _, a := range r.analyzers {
		fs, err := a.Check(ctx, m)
		findings = append(findings, fs...)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return findings, firstErr
}

// DefaultRegistry returns a registry populated with the full 53-rule
// analyzer pack (Phase 11.2, 11.3, A2, A4, 9.3, 9.6).
//
// The default registry is what MigrationBundleReconciler calls during
// the plan phase. Operators can opt out of specific rules via
// SchemaPolicy.spec.disabledAnalyzers (added in a later phase).
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.RegisterAll(
		// Phase 11.2 base pack — structural safety
		&NoDropTable{},
		&NoDropColumn{},
		&PreferConcurrentIndexCreation{},
		&RequirePrimaryKey{},
		&NoAlterColumnTypeInPlace{},
		&NoAddRequiredFieldWithoutDefault{},
		&NoTruncate{},
		&NoGrantAll{},
		&RequireStatementTimeoutOnDDL{},
		&NoTransactionAroundConcurrentIndex{},
		// Phase 11.3 extended pack — convention + perf + operational safety
		&NoSerial{},
		&RequireTimestamptz{},
		&NoReservedIdentifier{},
		&MaxMigrationSize{},
		&NoCascadeDelete{},
		&RequireIndexOnFK{},
		&NoAlterColumnSetStorage{},
		&NoExplicitPublicSchema{},
		&RequireMigrationComment{},
		&NoAlterTableRename{},
		// Phase A4 cross-migration — track bundle-local schema evolution
		&BreakingChangeDetector{},
		// Phase A2 — lock-heavy operations
		&NoAddFKWithoutNotValid{},
		&NoAddCheckWithoutNotValid{},
		&NoUniqueConstraintDirect{},
		&NoSetNotNullDirect{},
		&NoVacuumFull{},
		&NoCluster{},
		&NoReindexWithoutConcurrently{},
		&NoDropIndexWithoutConcurrently{},
		&NoLockTableExplicit{},
		// Phase A2 — backward compatibility
		&NoRenameColumn{},
		&NoRenameConstraint{},
		&NoDropView{},
		&NoDropFunction{},
		&NoDropSequence{},
		// Phase A2 — DML safety
		&NoUpdateWithoutWhere{},
		&NoDeleteWithoutWhere{},
		&NoInsertSelectWithoutWhere{},
		&NoLargeValuesList{},
		&NoDisableTriggersAll{},
		// Phase A2 — transaction / session safety
		&NoCommitInMigration{},
		&NoRollbackInMigration{},
		&NoSetSessionReplicationRole{},
		&NoSetConstraintsDeferred{},
		// Phase A2 — PG type conventions
		&NoVarcharWithoutLimit{},
		&PreferJsonbOverJson{},
		&NoNumericWithoutPrecision{},
		&RequireIfNotExistsOnCreateTable{},
		&NoUuidGenerateV1{},
		// Phase A2 — identifier hygiene
		&MaxIdentifierLength{},
		&NoPgPrefixIdentifier{},
		// Phase 9.3 — rollback safety
		&RequireDownMigration{},
		// Phase 9.6 — cross-bundle breaking change detection
		&CrossBundleBreakDetector{},
	)
	return r
}

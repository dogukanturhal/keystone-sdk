// SPDX-License-Identifier: AGPL-3.0-or-later

// Package drift owns the schema-fingerprint inspector + baseline
// bookkeeping used by the DriftController.
//
// Strategy: instead of shelling out to pg_dump (not in distroless,
// version-skew prone, expensive on large databases), query
// information_schema directly for the structural shape of the schema:
//
//   - tables (name, kind)
//   - columns (table, name, ordinal, type, nullable, default)
//   - indexes (name, table, definition)
//   - constraints (name, table, type, definition)
//
// Canonicalise the result, hash it. Drift = hash mismatch vs baseline.
// Per-object diff comes in Phase 5.1.
package drift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	pg "github.com/dogukanturhal/keystone-sdk/go/sqlquote"
)

// Snapshot is the canonicalised structural shape of a schema. JSON-
// serialised in deterministic order so hashes are stable across runs.
type Snapshot struct {
	Schema            string         `json:"schema"`
	Tables            []TableShape   `json:"tables"`
	Indexes           []ObjectDDL    `json:"indexes"`
	Constraints       []ObjectDDL    `json:"constraints"`
	Enums             []EnumShape    `json:"enums,omitempty"`
	Extensions        []ExtShape     `json:"extensions,omitempty"`
	Sequences         []SeqShape     `json:"sequences,omitempty"`
	Functions         []FuncShape    `json:"functions,omitempty"`
	Policies          []PolicyShape  `json:"policies,omitempty"`
	Triggers          []TriggerShape `json:"triggers,omitempty"`
	MaterializedViews []MatViewShape `json:"materialized_views,omitempty"`
}

// ExtShape captures a PostgreSQL extension installed into the inspected
// schema.
//
// An extension is scoped to a database but installed into one schema, and
// only those installed into the schema being inspected are recorded — a
// Snapshot describes one schema, for extensions as for everything else it
// carries. An extension a schema depends on but does not own (the usual
// `pgcrypto` in `public`) is provisioned by LogicalDatabase.spec.extensions,
// which is the layer that owns database-scoped objects.
type ExtShape struct {
	Name   string `json:"name"`
	Schema string `json:"schema,omitempty"`
	// Version mirrors pg_extension.extversion — the installed version, which
	// `ALTER EXTENSION ... UPDATE TO` changes in place without touching the
	// name or the schema. Without it that upgrade is invisible to drift: the
	// extension's functions can change behaviour under a schema that reports
	// itself unchanged.
	//
	// Empty means "not recorded" — a snapshot written before this field
	// existed. pg_extension.extversion is NOT NULL, so a snapshot the current
	// inspector produced always carries it for every extension. `omitempty`
	// keeps a cleared value serialising byte-identically to those older
	// snapshots, which is what makes WithoutExtVersion a faithful projection.
	Version string `json:"version,omitempty"`
}

// PredatesExtVersion reports whether this snapshot was written before
// ExtShape.Version was modelled, and therefore cannot be compared on it.
//
// The inspector populates Version for every extension it records, so a
// single empty one means the whole snapshot predates the field. A snapshot
// with no extensions at all reports false: there is nothing the field could
// have recorded, so it is not missing anything and its JSON is already
// identical under both models.
func (s *Snapshot) PredatesExtVersion() bool {
	if s == nil {
		return false
	}
	for i := range s.Extensions {
		if s.Extensions[i].Version == "" {
			return true
		}
	}
	return false
}

// WithoutExtVersion returns a copy of the snapshot with Version cleared on
// every extension, which serialises byte-identically to a snapshot written
// before the field existed.
//
// The RLSForced counterpart's reasoning applies unchanged — see
// [Snapshot.WithoutRLSForce].
func (s *Snapshot) WithoutExtVersion() *Snapshot {
	if s == nil {
		return nil
	}
	out := *s
	out.Extensions = make([]ExtShape, len(s.Extensions))
	copy(out.Extensions, s.Extensions)
	for i := range out.Extensions {
		out.Extensions[i].Version = ""
	}
	return &out
}

// EnumShape captures a PostgreSQL enum type and its labels.
type EnumShape struct {
	Name   string   `json:"name"`
	Labels []string `json:"labels"`
}

// SeqShape captures a PostgreSQL sequence's properties.
type SeqShape struct {
	Name        string `json:"name"`
	DataType    string `json:"data_type"`
	IncrementBy int64  `json:"increment_by"`
	MinValue    int64  `json:"min_value"`
	MaxValue    int64  `json:"max_value"`
	StartValue  int64  `json:"start_value"`
}

// FuncShape captures a PostgreSQL function/procedure.
type FuncShape struct {
	Name       string `json:"name"`
	Args       string `json:"args"`
	Returns    string `json:"returns"`
	Language   string `json:"language"`
	Definition string `json:"definition"`
}

// TableShape is one table's column list.
type TableShape struct {
	Name           string        `json:"name"`
	Kind           string        `json:"kind"` // BASE TABLE, VIEW, FOREIGN, …
	Columns        []ColumnShape `json:"columns"`
	ViewDefinition string        `json:"view_definition,omitempty"` // populated for Kind=VIEW
	RLSEnabled     bool          `json:"rls_enabled,omitempty"`     // pg_class.relrowsecurity
	// RLSForced mirrors pg_class.relforcerowsecurity — whether row-level
	// security also applies to the table's OWNER.
	//
	// This is a separate bit from RLSEnabled and it is the one that usually
	// matters. ENABLE alone exempts the owner: if the application connects as
	// the role that owns its tables — the common case, and the case across
	// this platform — then ENABLE-without-FORCE means every policy on the
	// table is bypassed for exactly the connection the policies exist to
	// constrain. On a multi-tenant schema that is a cross-tenant read.
	//
	// It is captured because a Snapshot that omits it cannot represent the
	// difference between a protected table and an unprotected one. Hash() is
	// a digest of this struct, so an un-modelled bit is not merely missing
	// from the diff — `ALTER TABLE … NO FORCE ROW LEVEL SECURITY` produces a
	// byte-identical snapshot, an identical hash, and therefore no drift
	// event of any kind.
	//
	// It is a pointer because nil has to mean "this snapshot predates the
	// field", not "not forced". Snapshots are persisted, and the stored
	// baseline is only rewritten when an operator accepts drift — so after
	// this field ships, every baseline in the fleet is an old-model document
	// for as long as it takes someone to re-accept it. Decoding a missing key
	// as false would read every already-forced table as "FORCE was just
	// added" and report it, on every reconcile, forever. The inspector always
	// sets this, so nil occurs only for snapshots written before it existed.
	RLSForced *bool `json:"rls_forced,omitempty"` // pg_class.relforcerowsecurity
}

// PredatesRLSForce reports whether this snapshot was written before
// RLSForced was modelled, and therefore cannot be compared on it.
//
// The inspector populates RLSForced on every table, so a single nil is
// enough to date the whole document.
func (s *Snapshot) PredatesRLSForce() bool {
	if s == nil {
		return false
	}
	for i := range s.Tables {
		if s.Tables[i].RLSForced == nil {
			return true
		}
	}
	return false
}

// WithoutRLSForce returns a copy of the snapshot with RLSForced cleared on
// every table, which serialises byte-identically to a snapshot written
// before the field existed.
//
// This exists so a caller holding an old-model baseline can ask the only
// question that matters during the upgrade: did anything OTHER than the
// snapshot model change? Hashing this projection against the stored
// baseline hash answers it exactly — no heuristics, no version counter.
func (s *Snapshot) WithoutRLSForce() *Snapshot {
	if s == nil {
		return nil
	}
	out := *s
	out.Tables = make([]TableShape, len(s.Tables))
	copy(out.Tables, s.Tables)
	for i := range out.Tables {
		out.Tables[i].RLSForced = nil
	}
	return &out
}

// PolicyShape captures a row-level security policy from pg_policies.
type PolicyShape struct {
	Name       string   `json:"name"`
	Table      string   `json:"table"`
	Command    string   `json:"command"` // ALL/SELECT/INSERT/UPDATE/DELETE
	Permissive bool     `json:"permissive"`
	Roles      []string `json:"roles,omitempty"`
	Using      string   `json:"using,omitempty"`
	WithCheck  string   `json:"with_check,omitempty"`
}

// TriggerShape captures a trigger binding from pg_trigger.
type TriggerShape struct {
	Name       string   `json:"name"`
	Table      string   `json:"table"`
	Timing     string   `json:"timing"` // BEFORE/AFTER/INSTEAD OF
	Events     []string `json:"events"` // INSERT, UPDATE, DELETE, TRUNCATE
	ForEachRow bool     `json:"for_each_row"`
	Function   string   `json:"function"`
	When       string   `json:"when,omitempty"`
}

// MatViewShape captures a materialized view from pg_matviews.
type MatViewShape struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
}

// ColumnShape is one column. type_name canonicalisation: pg
// information_schema reports both data_type ("text") and
// udt_name ("text"); we record both for forward-compat.
type ColumnShape struct {
	Name     string `json:"name"`
	Ordinal  int    `json:"ordinal"`
	DataType string `json:"data_type"`
	UDTName  string `json:"udt_name"`
	Nullable bool   `json:"nullable"`
	Default  string `json:"default,omitempty"`

	// FormattedType is format_type(atttypid, atttypmod) — the type with its
	// modifiers intact: "character varying(64)", "numeric(20,2)",
	// "geography(Point,4326)".
	//
	// information_schema.data_type reports the type family without modifiers,
	// so a snapshot built from data_type alone silently widens varchar(64) to
	// unbounded varchar and collapses geography(Point,4326) to bare geography.
	// Round-tripping such a snapshot through the differ authors DDL that drops
	// length limits and PostGIS type/SRID constraints without saying so.
	FormattedType string `json:"formatted_type,omitempty"`

	// Generated is the STORED generation expression, or "" for an ordinary
	// column.
	//
	// A generated column carries its expression in
	// information_schema.generation_expression, never in column_default, so a
	// snapshot that reads only the default records the column as ordinary. The
	// differ then authors ADD COLUMN without GENERATED ... STORED: the column
	// exists, is silently always NULL, and nothing recomputes it.
	Generated string `json:"generated,omitempty"`

	// Identity is pg_attribute.attidentity: "" (none), "a" (GENERATED ALWAYS),
	// or "d" (GENERATED BY DEFAULT).
	//
	// Without this a snapshot cannot distinguish a generated key from a plain
	// NOT NULL column, so the differ authors CREATE TABLE without the identity
	// clause. That applies cleanly and then every insert fails with
	// 23502 null value in column "id" — the migration looks correct until the
	// first write.
	Identity string `json:"identity,omitempty"`
}

// ObjectDDL is a generic name+definition pair used for indexes and
// constraints — these are read straight from pg_indexes and
// pg_constraint where the definition is the canonical truth.
type ObjectDDL struct {
	Name       string `json:"name"`
	Table      string `json:"table"`
	Type       string `json:"type"` // index: btree/hash/etc; constraint: PRIMARY KEY/CHECK/...
	Definition string `json:"definition"`
}

// Inspector queries the live schema and returns Snapshot. The pool MUST
// be connected to the database hosting the schema.
type Inspector struct {
	pool *pgxpool.Pool
}

// NewInspector binds the inspector to a pgx pool.
func NewInspector(pool *pgxpool.Pool) *Inspector {
	return &Inspector{pool: pool}
}

// Inspect queries information_schema + pg_indexes + pg_constraint for
// the named schema and returns a deterministic Snapshot.
func (i *Inspector) Inspect(ctx context.Context, schema string) (*Snapshot, error) {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return nil, err
	}

	out := &Snapshot{Schema: schema}

	// Tables.
	tableRows, err := i.pool.Query(ctx, `
		SELECT table_name, table_type
		  FROM information_schema.tables
		 WHERE table_schema = $1
		   AND table_name NOT IN ('schema_migrations', 'keystone_baselines', 'keystone_schema_migrations', 'keystone_smoke_marker', 'keystone_pipeline_test_sentinel', 'keystone_e2e_test', 'keystone_e2e_audit_test')
		   -- Exclude objects an extension owns. CREATE EXTENSION installs its own
		   -- catalog tables and views into a schema — PostGIS alone contributes
		   -- spatial_ref_sys, geometry_columns and geography_columns — and without
		   -- this filter the inspector reads them as application schema. The differ
		   -- then authors CREATE TABLE spatial_ref_sys against a database where
		   -- PostGIS already created it, and the migration fails with
		   -- 42P07 relation "spatial_ref_sys" already exists.
		   --
		   -- deptype 'e' is exactly "this object is a member of an extension", so the
		   -- extension is represented by its CREATE EXTENSION statement and by nothing
		   -- else.
		   AND NOT EXISTS (
		       SELECT 1
		         FROM pg_depend dep
		         JOIN pg_class  pc ON pc.oid = dep.objid
		         JOIN pg_namespace pn ON pn.oid = pc.relnamespace
		        WHERE pn.nspname = $1
		          AND pc.relname = table_name
		          AND dep.classid = 'pg_class'::regclass
		          AND dep.deptype = 'e'
		   )
		 ORDER BY table_name
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query tables: %w", err)
	}
	defer tableRows.Close()

	for tableRows.Next() {
		var t TableShape
		if err := tableRows.Scan(&t.Name, &t.Kind); err != nil {
			return nil, fmt.Errorf("scan table: %w", err)
		}
		out.Tables = append(out.Tables, t)
	}
	if err := tableRows.Err(); err != nil {
		return nil, fmt.Errorf("table rows: %w", err)
	}

	// Build the name→shape pointer map AFTER all appends are done.
	// Capturing &out.Tables[i] from inside the Scan loop would retain
	// pointers into an old backing array once a subsequent append
	// triggered a slice reallocation; any view definitions or columns
	// written through those stale pointers would be silently lost for
	// the first N-1 tables whenever N crossed a capacity doubling.
	tableMap := make(map[string]*TableShape, len(out.Tables))
	for i := range out.Tables {
		tableMap[out.Tables[i].Name] = &out.Tables[i]
	}

	// View definitions — populate ViewDefinition for VIEW entries.
	//
	// Use pg_get_viewdef(oid, pretty=true) rather than
	// information_schema.views.view_definition. Two reasons:
	//
	//  1. Canonical form. information_schema.views.view_definition is the
	//     raw ruleutils output: it fully-parenthesises every expression
	//     and join — `sum((a * b))`, `((ap.id = ta.addon_id))`,
	//     `(0)::bigint`, `FROM ((((t CROSS JOIN q) LEFT JOIN ...)))`.
	//     pg_get_viewdef(oid, true) is the PRETTY-printed form that
	//     strips those redundant parens — the exact form `\d+`, pgAdmin,
	//     and a hand `pg_get_viewdef` capture all produce, i.e. the form
	//     humans author spec.views[].query in. The differ's
	//     normaliseViewBody collapses whitespace/case/quotes but does NOT
	//     re-parenthesise, so an info_schema-form observed body never
	//     equals a pretty-form desired body → the differ re-emits
	//     `CREATE OR REPLACE VIEW` every reconcile, forever (the schema
	//     never converges to Ready). Reading the pretty form here closes
	//     that loop for the whole view class. This also makes views
	//     consistent with how the inspector already reads functions
	//     (pg_get_functiondef, below) and materialized views
	//     (pg_matviews.definition, which PG itself renders via
	//     pg_get_viewdef pretty form).
	//
	//  2. Robustness. information_schema.views.view_definition is NULL
	//     when the caller lacks USAGE on the view's schema or EXECUTE on
	//     a function it references (Falcon-ID's keystone_admin hits this
	//     on the legacy audit views). pg_get_viewdef reconstructs from
	//     the catalog regardless of privilege on referenced objects.
	//
	// relkind = 'v' is the exact set information_schema.views exposed
	// (regular views only); materialized views (relkind 'm') are
	// inspected separately below. COALESCE guards the theoretical NULL.
	viewRows, err := i.pool.Query(ctx, `
		SELECT c.relname AS table_name,
		       COALESCE(pg_get_viewdef(c.oid, true), '') AS view_definition
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = $1
		   AND c.relkind = 'v'
		 ORDER BY c.relname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query views: %w", err)
	}
	defer viewRows.Close()
	for viewRows.Next() {
		var name, def string
		if err := viewRows.Scan(&name, &def); err != nil {
			return nil, fmt.Errorf("scan view: %w", err)
		}
		if t, ok := tableMap[name]; ok {
			t.ViewDefinition = def
		}
	}
	if err := viewRows.Err(); err != nil {
		return nil, fmt.Errorf("view rows: %w", err)
	}

	// Columns — single query for all tables in the schema, distributed
	// into the per-table slices.
	colRows, err := i.pool.Query(ctx, `
		SELECT c.table_name, c.column_name, c.ordinal_position,
		       c.data_type, c.udt_name,
		       (c.is_nullable = 'YES') AS nullable,
		       COALESCE(c.column_default, '') AS column_default,
		       COALESCE(format_type(a.atttypid, a.atttypmod), '') AS formatted_type,
		       COALESCE(a.attidentity::text, '') AS identity,
		       COALESCE(c.generation_expression, '') AS generation_expression
		  FROM information_schema.columns c
		  LEFT JOIN pg_namespace n ON n.nspname = c.table_schema
		  LEFT JOIN pg_class     k ON k.relname = c.table_name AND k.relnamespace = n.oid
		  LEFT JOIN pg_attribute a ON a.attrelid = k.oid
		                          AND a.attname = c.column_name
		                          AND NOT a.attisdropped
		 WHERE c.table_schema = $1
		   AND c.table_name NOT IN ('schema_migrations', 'keystone_baselines', 'keystone_schema_migrations', 'keystone_smoke_marker', 'keystone_pipeline_test_sentinel', 'keystone_e2e_test', 'keystone_e2e_audit_test')
		 ORDER BY c.table_name, c.ordinal_position
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query columns: %w", err)
	}
	defer colRows.Close()

	for colRows.Next() {
		var (
			tname string
			c     ColumnShape
		)
		if err := colRows.Scan(&tname, &c.Name, &c.Ordinal,
			&c.DataType, &c.UDTName, &c.Nullable, &c.Default,
			&c.FormattedType, &c.Identity, &c.Generated); err != nil {
			return nil, fmt.Errorf("scan column: %w", err)
		}
		t, ok := tableMap[tname]
		if !ok {
			// Race: table appeared between queries; skip rather than fail.
			continue
		}
		t.Columns = append(t.Columns, c)
	}
	if err := colRows.Err(); err != nil {
		return nil, fmt.Errorf("column rows: %w", err)
	}

	// Indexes — pg_indexes gives us the CREATE INDEX statement verbatim.
	idxRows, err := i.pool.Query(ctx, `
		SELECT indexname, tablename, indexdef
		  FROM pg_indexes
		 WHERE schemaname = $1
		 ORDER BY tablename, indexname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query indexes: %w", err)
	}
	defer idxRows.Close()
	for idxRows.Next() {
		var o ObjectDDL
		if err := idxRows.Scan(&o.Name, &o.Table, &o.Definition); err != nil {
			return nil, fmt.Errorf("scan index: %w", err)
		}
		o.Type = "index"
		out.Indexes = append(out.Indexes, o)
	}
	if err := idxRows.Err(); err != nil {
		return nil, fmt.Errorf("index rows: %w", err)
	}

	// Constraints — join pg_constraint with pg_namespace + pg_class to
	// get the schema scope and the human-readable definition.
	cstRows, err := i.pool.Query(ctx, `
		SELECT con.conname,
		       cls.relname,
		       con.contype,
		       pg_get_constraintdef(con.oid) AS def
		  FROM pg_constraint con
		  JOIN pg_class      cls ON cls.oid = con.conrelid
		  JOIN pg_namespace  ns  ON ns.oid  = cls.relnamespace
		 WHERE ns.nspname = $1
		   -- Extension-owned tables are not in the snapshot, so their constraints
		   -- must not be either.
		   AND NOT EXISTS (
		       SELECT 1 FROM pg_depend dep
		        WHERE dep.objid = cls.oid
		          AND dep.classid = 'pg_class'::regclass
		          AND dep.deptype = 'e'
		   )
		 ORDER BY cls.relname, con.conname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query constraints: %w", err)
	}
	defer cstRows.Close()
	for cstRows.Next() {
		var (
			o    ObjectDDL
			ctyp byte
		)
		if err := cstRows.Scan(&o.Name, &o.Table, &ctyp, &o.Definition); err != nil {
			return nil, fmt.Errorf("scan constraint: %w", err)
		}
		o.Type = constraintTypeName(ctyp)
		out.Constraints = append(out.Constraints, o)
	}
	if err := cstRows.Err(); err != nil {
		return nil, fmt.Errorf("constraint rows: %w", err)
	}

	// Extensions installed INTO the schema being inspected.
	//
	// PostgreSQL scopes an extension to a database and installs it into one
	// schema. This query is deliberately restricted to that schema, so a
	// Snapshot means the same thing for extensions as it does for every
	// other object it carries: the contents of one schema.
	//
	// Reporting them database-wide — the previous behaviour — is wrong in a
	// multi-tenant database, which is Keystone's normal deployment. Every
	// tenant schema's snapshot picked up every other tenant's extensions, so
	// installing one extension for one tenant re-hashed the drift baseline of
	// all of them and produced a DriftReport per schema, none of which
	// described a real change. It also wrote another tenant's schema name
	// into the authored `CREATE EXTENSION ... SCHEMA <other-tenant>`.
	//
	// Extensions a schema depends on but does not own — the common
	// `pgcrypto` in `public` supplying gen_random_uuid() — are provisioned a
	// layer up, by LogicalDatabase.spec.extensions, which runs before any
	// schema exists. That is the right layer for a database-scoped object; a
	// SchemaDefinition describing a schema should not be installing shared
	// infrastructure. Nothing is lost by scoping here, and the differ never
	// drops an extension anyway (see diffExtensions).
	//
	// Built-in plpgsql is excluded: it is present in every database by
	// default, so declaring it would make every generated spec carry a line
	// that means nothing.
	extRows, err := i.pool.Query(ctx, `
		SELECT e.extname, n.nspname, e.extversion
		  FROM pg_extension e
		  JOIN pg_namespace n ON n.oid = e.extnamespace
		 WHERE e.extname <> 'plpgsql'
		   AND n.nspname = $1
		 ORDER BY e.extname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query extensions: %w", err)
	}
	for extRows.Next() {
		var x ExtShape
		if err := extRows.Scan(&x.Name, &x.Schema, &x.Version); err != nil {
			extRows.Close()
			return nil, fmt.Errorf("scan extension: %w", err)
		}
		out.Extensions = append(out.Extensions, x)
	}
	extRows.Close()
	if err := extRows.Err(); err != nil {
		return nil, fmt.Errorf("extension rows: %w", err)
	}

	// Enums — query pg_type + pg_enum for user-defined enum types in
	// this schema. Labels are ordered by enumsortorder.
	enumRows, err := i.pool.Query(ctx, `
		SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder)
		  FROM pg_type t
		  JOIN pg_enum e ON e.enumtypid = t.oid
		  JOIN pg_namespace n ON n.oid = t.typnamespace
		 WHERE n.nspname = $1
		 GROUP BY t.typname
		 ORDER BY t.typname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query enums: %w", err)
	}
	defer enumRows.Close()
	for enumRows.Next() {
		var es EnumShape
		if err := enumRows.Scan(&es.Name, &es.Labels); err != nil {
			return nil, fmt.Errorf("scan enum: %w", err)
		}
		out.Enums = append(out.Enums, es)
	}
	if err := enumRows.Err(); err != nil {
		return nil, fmt.Errorf("enum rows: %w", err)
	}

	// Sequences — query pg_sequences (PG 10+) for sequence metadata.
	seqRows, err := i.pool.Query(ctx, `
		SELECT s.sequencename,
		       s.data_type,
		       s.increment_by,
		       s.min_value,
		       s.max_value,
		       s.start_value
		  FROM pg_sequences s
		 WHERE s.schemaname = $1
		   -- Exclude sequences owned by a column. An identity column (deptype
		   -- 'i') or a serial column (deptype 'a') creates its own sequence as
		   -- an implementation detail; it is not an independent object.
		   --
		   -- Emitting it separately is actively harmful: the authored migration
		   -- runs CREATE SEQUENCE foo_id_seq, then CREATE TABLE ... GENERATED BY
		   -- DEFAULT AS IDENTITY finds that name taken and silently creates
		   -- foo_id_seq1. The database ends up with two sequences, one orphaned,
		   -- and the next diff churns on the difference forever.
		   AND NOT EXISTS (
		       SELECT 1
		         FROM pg_depend d
		         JOIN pg_class c ON c.oid = d.objid AND c.relkind = 'S'
		         JOIN pg_namespace n ON n.oid = c.relnamespace
		        WHERE n.nspname = s.schemaname
		          AND c.relname = s.sequencename
		          AND d.classid = 'pg_class'::regclass
		          AND d.refclassid = 'pg_class'::regclass
		          AND d.deptype IN ('a', 'i')
		   )
		 ORDER BY s.sequencename
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query sequences: %w", err)
	}
	defer seqRows.Close()
	for seqRows.Next() {
		var ss SeqShape
		if err := seqRows.Scan(&ss.Name, &ss.DataType,
			&ss.IncrementBy, &ss.MinValue, &ss.MaxValue, &ss.StartValue); err != nil {
			return nil, fmt.Errorf("scan sequence: %w", err)
		}
		out.Sequences = append(out.Sequences, ss)
	}
	if err := seqRows.Err(); err != nil {
		return nil, fmt.Errorf("sequence rows: %w", err)
	}

	// Functions — query pg_proc for user-defined functions in the schema.
	// pg_get_functiondef gives us the full CREATE FUNCTION statement.
	//
	// Extension-owned functions (pgcrypto's armor()/crypt(), uuid-ossp's
	// uuid_generate_v4(), etc.) are filtered out via the LEFT JOIN on
	// pg_depend with deptype='e'. Without this filter the inspector
	// surfaces ~30 pgcrypto C-language functions on every schema scan,
	// which then leak into keystonectl-inspect-generated SchemaDefinitions
	// and produce CREATE OR REPLACE DDL on every reconcile (the bodies
	// can't be authored by users — they're CREATE EXTENSION-installed).
	// Any object dependent on an extension (deptype 'e' = AUTO/EXTENSION)
	// is owned by the extension and managed via CREATE/DROP EXTENSION.
	funcRows, err := i.pool.Query(ctx, `
		SELECT p.proname,
		       pg_get_function_arguments(p.oid) AS args,
		       pg_get_function_result(p.oid) AS returns,
		       l.lanname AS language,
		       pg_get_functiondef(p.oid) AS definition
		  FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		  JOIN pg_language l ON l.oid = p.prolang
		  LEFT JOIN pg_depend d
		         ON d.objid = p.oid
		        AND d.classid = 'pg_proc'::regclass
		        AND d.deptype = 'e'
		 WHERE n.nspname = $1
		   AND p.prokind IN ('f', 'p')
		   AND d.objid IS NULL
		 ORDER BY p.proname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query functions: %w", err)
	}
	defer funcRows.Close()
	for funcRows.Next() {
		var fs FuncShape
		if err := funcRows.Scan(&fs.Name, &fs.Args, &fs.Returns,
			&fs.Language, &fs.Definition); err != nil {
			return nil, fmt.Errorf("scan function: %w", err)
		}
		out.Functions = append(out.Functions, fs)
	}
	if err := funcRows.Err(); err != nil {
		return nil, fmt.Errorf("function rows: %w", err)
	}

	// RLS flags per table — pg_class.relrowsecurity and
	// pg_class.relforcerowsecurity live outside information_schema so we
	// cross-reference by relname.
	//
	// Both bits are selected for every ordinary table rather than filtering
	// to `relrowsecurity = true`. The filter would be the cheaper query and
	// is what this did originally, but it cannot express the state that
	// matters: a table whose RLS was turned OFF looks, to a filtered query,
	// exactly like a table that never had it. Reading the pair unconditionally
	// lets the snapshot record protection being REMOVED, which is the event
	// worth alerting on.
	rlsRows, err := i.pool.Query(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = $1
		   AND c.relkind = 'r'
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query rls flags: %w", err)
	}
	defer rlsRows.Close()
	for rlsRows.Next() {
		var name string
		var enabled, forced bool
		if err := rlsRows.Scan(&name, &enabled, &forced); err != nil {
			return nil, fmt.Errorf("scan rls: %w", err)
		}
		if t, ok := tableMap[name]; ok {
			t.RLSEnabled = enabled
			// Always non-nil: an inspected table's FORCE state is known,
			// and nil is reserved for snapshots predating the field.
			forced := forced
			t.RLSForced = &forced
		}
	}
	if err := rlsRows.Err(); err != nil {
		return nil, fmt.Errorf("rls rows: %w", err)
	}

	// Policies — pg_policies is a view over pg_policy + pg_roles that
	// already handles role OID → name translation, qual / with_check
	// quoting, and permissive/restrictive classification.
	polRows, err := i.pool.Query(ctx, `
		SELECT tablename,
		       policyname,
		       permissive,
		       COALESCE(roles, '{public}'::name[]) AS roles,
		       COALESCE(cmd, 'ALL') AS cmd,
		       COALESCE(qual, '') AS using_expr,
		       COALESCE(with_check, '') AS with_check
		  FROM pg_policies
		 WHERE schemaname = $1
		 ORDER BY tablename, policyname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer polRows.Close()
	for polRows.Next() {
		var (
			p          PolicyShape
			permissive string
			roles      []string
		)
		if err := polRows.Scan(&p.Table, &p.Name, &permissive, &roles,
			&p.Command, &p.Using, &p.WithCheck); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		p.Permissive = permissive == "PERMISSIVE"
		p.Roles = roles
		out.Policies = append(out.Policies, p)
	}
	if err := polRows.Err(); err != nil {
		return nil, fmt.Errorf("policy rows: %w", err)
	}

	// Triggers — pg_trigger encodes timing/events as a bitfield in tgtype.
	// Bit layout (postgres docs):
	//   bit 0 (1)  — ROW (vs STATEMENT)
	//   bit 1 (2)  — BEFORE (vs AFTER)
	//   bit 2 (4)  — INSERT
	//   bit 3 (8)  — DELETE
	//   bit 4 (16) — UPDATE
	//   bit 5 (32) — TRUNCATE
	//   bit 6 (64) — INSTEAD OF
	// tgisinternal=true covers FK-enforcement triggers etc.; skip those.
	//
	// The optional WHEN clause is pulled from pg_get_triggerdef rather
	// than pg_get_expr(tgqual, tgrelid) — the latter errors with
	// "expression contains variables of more than one relation" when the
	// trigger function's body references NEW/OLD, which counts as a
	// second relation to the expression walker. pg_get_triggerdef never
	// trips that check and is already the canonical reconstructor used
	// by pg_dump.
	trgRows, err := i.pool.Query(ctx, `
		SELECT c.relname                                 AS tbl,
		       t.tgname                                  AS name,
		       CASE WHEN (t.tgtype::integer & 64) != 0 THEN 'INSTEAD OF'
		            WHEN (t.tgtype::integer & 2)  != 0 THEN 'BEFORE'
		            ELSE 'AFTER' END                     AS timing,
		       ARRAY_REMOVE(ARRAY[
		           CASE WHEN (t.tgtype::integer & 4)  != 0 THEN 'INSERT'   END,
		           CASE WHEN (t.tgtype::integer & 8)  != 0 THEN 'DELETE'   END,
		           CASE WHEN (t.tgtype::integer & 16) != 0 THEN 'UPDATE'   END,
		           CASE WHEN (t.tgtype::integer & 32) != 0 THEN 'TRUNCATE' END
		       ], NULL)                                  AS events,
		       (t.tgtype::integer & 1) != 0              AS for_each_row,
		       p.proname                                 AS fn,
		       pg_get_triggerdef(t.oid)                  AS trigger_def
		  FROM pg_trigger t
		  JOIN pg_class c ON c.oid = t.tgrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_proc p ON p.oid = t.tgfoid
		 WHERE n.nspname = $1
		   AND NOT t.tgisinternal
		 ORDER BY c.relname, t.tgname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query triggers: %w", err)
	}
	defer trgRows.Close()
	for trgRows.Next() {
		var (
			tr  TriggerShape
			def string
		)
		if err := trgRows.Scan(&tr.Table, &tr.Name, &tr.Timing,
			&tr.Events, &tr.ForEachRow, &tr.Function, &def); err != nil {
			return nil, fmt.Errorf("scan trigger: %w", err)
		}
		tr.When = extractTriggerWhen(def)
		out.Triggers = append(out.Triggers, tr)
	}
	if err := trgRows.Err(); err != nil {
		return nil, fmt.Errorf("trigger rows: %w", err)
	}

	// Materialized views — pg_matviews is the stable (PG 9.3+) catalog view.
	// The definition column carries the SELECT verbatim.
	mvRows, err := i.pool.Query(ctx, `
		SELECT matviewname, definition
		  FROM pg_matviews
		 WHERE schemaname = $1
		 ORDER BY matviewname
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("query matviews: %w", err)
	}
	defer mvRows.Close()
	for mvRows.Next() {
		var mv MatViewShape
		if err := mvRows.Scan(&mv.Name, &mv.Definition); err != nil {
			return nil, fmt.Errorf("scan matview: %w", err)
		}
		out.MaterializedViews = append(out.MaterializedViews, mv)
	}
	if err := mvRows.Err(); err != nil {
		return nil, fmt.Errorf("matview rows: %w", err)
	}

	// Defensive sort — pgx guarantees row order from ORDER BY but not
	// across multiple queries (and we may extend later).
	sort.Slice(out.Tables, func(i, j int) bool { return out.Tables[i].Name < out.Tables[j].Name })
	for ti := range out.Tables {
		cols := out.Tables[ti].Columns
		sort.Slice(cols, func(i, j int) bool { return cols[i].Ordinal < cols[j].Ordinal })
	}
	sort.Slice(out.Indexes, func(i, j int) bool {
		if out.Indexes[i].Table != out.Indexes[j].Table {
			return out.Indexes[i].Table < out.Indexes[j].Table
		}
		return out.Indexes[i].Name < out.Indexes[j].Name
	})
	sort.Slice(out.Constraints, func(i, j int) bool {
		if out.Constraints[i].Table != out.Constraints[j].Table {
			return out.Constraints[i].Table < out.Constraints[j].Table
		}
		return out.Constraints[i].Name < out.Constraints[j].Name
	})

	return out, nil
}

// Hash returns a deterministic SHA-256 hex over the snapshot's
// canonical JSON representation. JSON encoder writes object fields in
// struct order which is stable across builds.
func Hash(s *Snapshot) (string, error) {
	enc, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal snapshot: %w", err)
	}
	sum := sha256.Sum256(enc)
	return hex.EncodeToString(sum[:]), nil
}

// ResolveColumnType turns information_schema.columns (data_type, udt_name)
// into a SchemaDefinition-compatible type string.
//
// information_schema.data_type returns descriptive labels rather than the
// literal PG type for two families:
//
//   - ARRAY: the actual element type lives in udt_name with a leading
//     underscore (pg_type convention, e.g. _text for text[]).
//   - USER-DEFINED: udt_name holds the real type name (enum, composite,
//     domain). data_type reports the category, not the type.
//
// For every other category data_type is already the usable PG type
// (e.g. "character varying", "timestamp with time zone").
//
// Single source of truth: keystonectl uses this at SD-render time to
// emit "text[]" / "tenant_type" instead of the raw labels, and the
// differ uses it at diff-comparison time to match observed against
// SD-declared types. Without a shared resolver, a SD that declares
// "text[]" reads back "ARRAY" from the inspector and fires a
// type-drift warning on every reconcile (observed 2026-05-06: 70+
// false-positive warnings on example-service-tenant-desired diff).
// ResolveColumnTypeShape is the modifier-preserving resolver. It prefers
// format_type output, which already carries length, precision and PostGIS
// typmod, and falls back to the data_type/udt_name pair for snapshots taken
// before FormattedType existed.
func ResolveColumnTypeShape(c ColumnShape) string {
	if c.FormattedType == "" {
		return ResolveColumnType(c.DataType, c.UDTName)
	}
	return stripTypeSchema(c.FormattedType, c.UDTName)
}

// stripTypeSchema removes a schema qualifier from a format_type result when
// the unqualified remainder is the type's own udt_name.
//
// format_type qualifies any type not on the current search_path, so a
// user-defined type reads back as "keystone_dev_2c3a8f55f325.record_kind".
// The differ normalises a sql:// desired schema by applying it to a scratch
// schema whose name is content-hashed, so the qualifier differs between the
// two sides of every diff — every enum column would report type drift on
// every run, and none of it would be real. Only the qualifier is dropped;
// modifiers such as (Point,4326) are on the other side of the name and are
// preserved.
func stripTypeSchema(formatted, udtName string) string {
	if udtName == "" {
		return formatted
	}

	// Consider only the part before any modifier list: "a.b(Point,4326)" must
	// be split on the dot in "a.b", never on one inside the parentheses.
	head := formatted
	if i := strings.IndexByte(head, '('); i >= 0 {
		head = head[:i]
	}

	dot := strings.LastIndexByte(head, '.')
	if dot < 0 {
		return formatted
	}

	bare := strings.Trim(head[dot+1:], `"`)
	if bare != udtName {
		// Qualified, but not by its own name — leave it alone rather than
		// guessing.
		return formatted
	}

	return bare + formatted[len(head):]
}

// IdentityClause renders attidentity as the SQL fragment that recreates it,
// or "" when the column is not an identity column.
func IdentityClause(identity string) string {
	switch identity {
	case "a":
		return "GENERATED ALWAYS AS IDENTITY"
	case "d":
		return "GENERATED BY DEFAULT AS IDENTITY"
	default:
		return ""
	}
}

func ResolveColumnType(dataType, udtName string) string {
	switch dataType {
	case "ARRAY":
		if len(udtName) > 0 && udtName[0] == '_' {
			return udtName[1:] + "[]"
		}
		return udtName + "[]"
	case "USER-DEFINED":
		return udtName
	default:
		return dataType
	}
}

// extractTriggerWhen pulls the WHEN clause out of a CREATE TRIGGER DDL
// string emitted by pg_get_triggerdef. Returns empty string when the
// trigger has no WHEN. The clause body is returned with surrounding
// parentheses stripped so it matches DesiredTrigger.When semantics.
func extractTriggerWhen(def string) string {
	idx := indexCaseInsensitive(def, " WHEN (")
	if idx < 0 {
		return ""
	}
	rest := def[idx+len(" WHEN ("):]
	// Walk forward counting parens until the matching close, which marks
	// the end of the WHEN expression.
	depth := 1
	for i, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return rest[:i]
			}
		}
	}
	return ""
}

// indexCaseInsensitive returns the first index of sub in s ignoring
// case, or -1 if not found. sub must already be upper-case for the
// comparison to short-circuit on the common no-WHEN trigger path.
func indexCaseInsensitive(s, sub string) int {
	ls := len(s)
	lsu := len(sub)
	for i := 0; i <= ls-lsu; i++ {
		match := true
		for j := 0; j < lsu; j++ {
			a := s[i+j]
			if a >= 'a' && a <= 'z' {
				a -= 'a' - 'A'
			}
			if a != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// constraintTypeName maps PG's pg_constraint.contype byte codes to
// human-readable strings. Stable across PG versions.
func constraintTypeName(b byte) string {
	switch b {
	case 'p':
		return "PRIMARY KEY"
	case 'u':
		return "UNIQUE"
	case 'f':
		return "FOREIGN KEY"
	case 'c':
		return "CHECK"
	case 'x':
		return "EXCLUDE"
	case 't':
		return "TRIGGER"
	default:
		return "OTHER"
	}
}

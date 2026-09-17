// SPDX-License-Identifier: Apache-2.0

// Package schemasource resolves a "schema source reference" into a
// Keystone desired-state SchemaDefinitionSpec, normalising every input
// through a common representation.
//
// A source reference names where a desired (or current) schema lives:
//
//	yaml://path/to/schema-definition.yaml   declarative schema-as-code
//	sql://path/to/schema.sql                raw DDL (hand-written, ORM
//	file://path/to/schema.sql               provider output, EF Core
//	                                        GenerateCreateScript, pg_dump)
//	db://postgres://user:pw@host/db?schema=public
//	                                        an existing database already
//	                                        holding the desired shape
//	exec://dotnet keystone-ef               a provider program that prints
//	                                        the desired schema as DDL on
//	                                        stdout (any ORM, any runtime)
//
// The unifying idea — mirroring Atlas's "dev database" — is that a
// throwaway PostgreSQL schema is the universal normaliser. SQL DDL from
// any origin (including any ORM that can emit CREATE statements) is
// applied to a scratch schema on a dev database and read back with the
// same drift.Inspector that reads production. That is why Keystone
// supports "schema from code" for both declarative SQL/YAML and ORM
// entities without re-implementing a single ORM's model layer: the ORM
// emits SQL, the dev database turns SQL into a Snapshot, and the existing
// differ takes it from there.
package schemasource

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"sigs.k8s.io/yaml"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	"github.com/dogukanturhal/keystone-sdk/go/migration"
	"github.com/dogukanturhal/keystone-sdk/go/schemaspec"
	pg "github.com/dogukanturhal/keystone-sdk/go/sqlquote"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Scheme identifies the kind of a parsed source reference.
type Scheme string

const (
	// SchemeYAML is a SchemaDefinition YAML file (declarative).
	SchemeYAML Scheme = "yaml"
	// SchemeSQL is a raw DDL file, normalised through a dev database.
	SchemeSQL Scheme = "sql"
	// SchemeDB is a live database inspected directly.
	SchemeDB Scheme = "db"
	// SchemeExec is a provider program whose stdout is DDL, normalised
	// through a dev database exactly like SchemeSQL. This is the ORM
	// integration seam: any ORM that can render CREATE statements — EF
	// Core, GORM, Prisma, SQLAlchemy, Django, Ecto — plugs in without
	// Keystone learning anything about its model layer.
	//
	// Running a program is a capability, not a parse result: it is
	// refused unless the caller sets Resolver.AllowExec. See Resolver.
	SchemeExec Scheme = "exec"
)

// Ref is a parsed source reference.
type Ref struct {
	Scheme Scheme
	// Path is the file path for yaml:// and sql:// references.
	Path string
	// DSN is the PostgreSQL connection string for db:// references.
	DSN string
	// Schema is the schema to inspect for db:// references when carried
	// in the reference (?schema=). Empty means the caller's default.
	Schema string
	// Program is the argv of an exec:// provider — never a shell string.
	// Populated by ParseRef from the reference text, or set directly by
	// callers that already hold a structured array (keystone.yaml).
	Program []string
}

// ParseRef parses a source reference string. Bare paths (no scheme) are
// classified by extension: .sql → SchemeSQL, .yaml/.yml → SchemeYAML.
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, fmt.Errorf("empty source reference")
	}
	switch {
	case strings.HasPrefix(s, "yaml://"):
		return Ref{Scheme: SchemeYAML, Path: strings.TrimPrefix(s, "yaml://")}, nil
	case strings.HasPrefix(s, "sql://"):
		return Ref{Scheme: SchemeSQL, Path: strings.TrimPrefix(s, "sql://")}, nil
	case strings.HasPrefix(s, "file://"):
		p := strings.TrimPrefix(s, "file://")
		if strings.HasSuffix(strings.ToLower(p), ".sql") {
			return Ref{Scheme: SchemeSQL, Path: p}, nil
		}
		return Ref{Scheme: SchemeYAML, Path: p}, nil
	case strings.HasPrefix(s, "exec://"):
		program, err := SplitProgram(strings.TrimPrefix(s, "exec://"))
		if err != nil {
			return Ref{}, err
		}
		return Ref{Scheme: SchemeExec, Program: program}, nil
	case strings.HasPrefix(s, "db://"):
		dsn := strings.TrimPrefix(s, "db://")
		// Allow db://<bare> as shorthand for a postgres:// DSN.
		if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
			dsn = "postgres://" + dsn
		}
		schema, clean, err := extractSchemaParam(dsn)
		if err != nil {
			return Ref{}, err
		}
		return Ref{Scheme: SchemeDB, DSN: clean, Schema: schema}, nil
	default:
		// Bare path: classify by extension.
		low := strings.ToLower(s)
		switch {
		case strings.HasSuffix(low, ".sql"):
			return Ref{Scheme: SchemeSQL, Path: s}, nil
		case strings.HasSuffix(low, ".yaml"), strings.HasSuffix(low, ".yml"):
			return Ref{Scheme: SchemeYAML, Path: s}, nil
		default:
			return Ref{}, fmt.Errorf("cannot classify source reference %q: prefix with yaml:// , sql:// , db:// or exec:// (or use a .sql/.yaml path)", s)
		}
	}
}

// extractSchemaParam pulls a `schema` query parameter out of a DSN and
// returns the schema plus the DSN with that parameter removed (so it is
// never passed to PostgreSQL, which would reject an unknown parameter).
func extractSchemaParam(dsn string) (schema, clean string, err error) {
	u, perr := url.Parse(dsn)
	if perr != nil {
		// Not a URL-style DSN (could be a keyword/value string); leave as-is.
		return "", dsn, nil //nolint:nilerr // keyword DSNs carry no schema param
	}
	q := u.Query()
	schema = q.Get("schema")
	if schema != "" {
		q.Del("schema")
		u.RawQuery = q.Encode()
	}
	return schema, u.String(), nil
}

// Resolver resolves source references with an explicit capability set.
//
// The zero Resolver is the safe one: it behaves exactly like the
// package-level ResolveDesired and refuses exec://. Running a program
// named by a reference is a privilege that only a developer-driven
// caller (keystonectl, a CI job) may grant. A reconciler resolving a
// reference that arrived in a CR spec must never set AllowExec — that
// would turn a namespace-scoped write into remote code execution inside
// the operator pod.
type Resolver struct {
	// AllowExec enables the exec:// scheme. Off by default, on purpose.
	AllowExec bool
	// ExecDir is the working directory for exec:// providers. Empty
	// means the current process's directory. Set this to the project
	// root so a provider resolves its ORM project relative to the
	// config file rather than to wherever the CLI was invoked.
	ExecDir string
	// ExecEnv is the environment for exec:// providers. Nil inherits the
	// parent environment — which is what an ORM provider normally needs
	// (PATH, DOTNET_ROOT, GOCACHE, connection strings).
	ExecEnv []string
	// ExecTimeout bounds a provider's runtime. Zero means
	// DefaultExecTimeout.
	ExecTimeout time.Duration
}

// ResolveDesired resolves ref into a desired-state SchemaDefinitionSpec
// with exec:// disabled. Equivalent to Resolver{}.ResolveDesired.
func ResolveDesired(ctx context.Context, ref Ref, devPool *pgxpool.Pool, defaultSchema string, opts schemaspec.Options) (*keystonev1alpha1.SchemaDefinitionSpec, error) {
	return Resolver{}.ResolveDesired(ctx, ref, devPool, defaultSchema, opts)
}

// ResolveDesired resolves ref into a desired-state SchemaDefinitionSpec.
//
//   - yaml:// reads the SchemaDefinition file (devPool unused).
//   - sql:// applies the DDL to a scratch schema on devPool, inspects it,
//     and converts the resulting Snapshot (devPool is REQUIRED).
//   - db:// opens its own connection to ref.DSN, inspects ref.Schema (or
//     defaultSchema when the ref carries none), and converts.
//
// opts is forwarded to schemaspec.FromSnapshot for the sql:// / db://
// paths (schemaRef / selector labels); it is ignored for yaml:// where
// the file already carries those fields.
func (r Resolver) ResolveDesired(ctx context.Context, ref Ref, devPool *pgxpool.Pool, defaultSchema string, opts schemaspec.Options) (*keystonev1alpha1.SchemaDefinitionSpec, error) {
	switch ref.Scheme {
	case SchemeYAML:
		return LoadSpecFile(ref.Path)
	case SchemeSQL:
		if devPool == nil {
			return nil, fmt.Errorf("sql:// source requires a --dev-url database to normalise the DDL")
		}
		ddl, err := os.ReadFile(ref.Path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", ref.Path, err)
		}
		snap, err := SnapshotFromDDL(ctx, devPool, string(ddl), defaultSchema)
		if err != nil {
			return nil, err
		}
		return schemaspec.FromSnapshot(snap, opts), nil
	case SchemeExec:
		if !r.AllowExec {
			return nil, fmt.Errorf("exec:// sources are disabled for this caller: running a provider program is opt-in (schemasource.Resolver.AllowExec)")
		}
		if devPool == nil {
			return nil, fmt.Errorf("exec:// source requires a --dev-url database to normalise the DDL")
		}
		ddl, err := runProgram(ctx, ref.Program, r.ExecDir, r.ExecEnv, r.ExecTimeout)
		if err != nil {
			return nil, err
		}
		snap, err := SnapshotFromDDL(ctx, devPool, ddl, defaultSchema)
		if err != nil {
			return nil, fmt.Errorf("normalise DDL from exec:// provider %q: %w",
				strings.Join(ref.Program, " "), err)
		}
		return schemaspec.FromSnapshot(snap, opts), nil
	case SchemeDB:
		schema := ref.Schema
		if schema == "" {
			schema = defaultSchema
		}
		pool, err := pgxpool.New(ctx, ref.DSN)
		if err != nil {
			return nil, fmt.Errorf("connect to db:// source: %w", err)
		}
		defer pool.Close()
		snap, err := drift.NewInspector(pool).Inspect(ctx, schema)
		if err != nil {
			return nil, fmt.Errorf("inspect db:// source schema %q: %w", schema, err)
		}
		return schemaspec.FromSnapshot(snap, opts), nil
	default:
		return nil, fmt.Errorf("unsupported source scheme %q", ref.Scheme)
	}
}

// LoadSpecFile reads a SchemaDefinition YAML — accepting either a full CR
// (apiVersion/kind/spec) or a bare spec document — into a spec.
func LoadSpecFile(path string) (*keystonev1alpha1.SchemaDefinitionSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var full struct {
		Spec keystonev1alpha1.SchemaDefinitionSpec `yaml:"spec" json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &full); err == nil && len(full.Spec.Tables) > 0 {
		return &full.Spec, nil
	}
	var spec keystonev1alpha1.SchemaDefinitionSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &spec, nil
}

// SnapshotFromDDL applies a DDL blob to a fresh, isolated scratch schema
// on devPool, inspects it, and returns the Snapshot — the canonical "dev
// database" normalisation. The scratch schema is created and dropped
// within the call. The DDL must be schema-relative (unqualified object
// names); the runner sets search_path to the scratch schema so objects
// land there.
//
// targetSchema is the logical schema the resulting snapshot should report
// (its .Schema and the schema qualifier embedded in inspected DDL such as
// index definitions). Pass the schema the diff will run against so the
// differ's index/object comparison is not confused by the throwaway
// scratch schema name.
func SnapshotFromDDL(ctx context.Context, devPool *pgxpool.Pool, ddl, targetSchema string) (*drift.Snapshot, error) {
	return materialize(ctx, devPool, map[string]string{"desired.up.sql": ddl}, []string{"desired.up.sql"}, targetSchema)
}

// SnapshotFromFiles replays an ordered set of migration files onto a
// scratch schema on devPool and inspects the result — the dev-replay
// basis for `migrate diff`'s current state. files maps name→content; the
// apply order is lexicographic by name (mirroring the runner). Pass the
// directory's *.up.sql files; down files must be excluded by the caller.
// targetSchema has the same meaning as in SnapshotFromDDL.
func SnapshotFromFiles(ctx context.Context, devPool *pgxpool.Pool, files map[string]string, targetSchema string) (*drift.Snapshot, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return materialize(ctx, devPool, files, names, targetSchema)
}

// materialize is the shared dev-database normaliser: create scratch
// schema → replay files via the production runner (which handles
// search_path, statement splitting, and CONCURRENTLY/tx mode) → inspect
// → drop scratch schema. Reusing migration.Runner means the dev replay is
// byte-for-byte the same apply path production uses, so the resulting
// Snapshot is high-fidelity.
func materialize(ctx context.Context, devPool *pgxpool.Pool, files map[string]string, names []string, targetSchema string) (snap *drift.Snapshot, err error) {
	if devPool == nil {
		return nil, fmt.Errorf("materialize: nil dev pool")
	}
	scratch, err := scratchSchemaName()
	if err != nil {
		return nil, err
	}
	if _, err := devPool.Exec(ctx, "CREATE SCHEMA "+pg.QuoteIdentifier(scratch)); err != nil {
		return nil, fmt.Errorf("create scratch schema: %w", err)
	}
	// Always tear the scratch schema down, even on failure. Use a
	// background context so cleanup runs even if ctx is already cancelled.
	defer func() {
		_, derr := devPool.Exec(context.Background(),
			"DROP SCHEMA IF EXISTS "+pg.QuoteIdentifier(scratch)+" CASCADE")
		if derr != nil && err == nil {
			err = fmt.Errorf("drop scratch schema %q: %w", scratch, derr)
		}
	}()

	runner, err := migration.NewRunner(devPool, scratch, "keystone_schema_migrations", "")
	if err != nil {
		return nil, fmt.Errorf("new runner: %w", err)
	}
	if err := runner.EnsureBookkeeping(ctx); err != nil {
		return nil, fmt.Errorf("ensure bookkeeping: %w", err)
	}
	src := &migration.ResolvedSource{Files: files, Names: names}
	src.ContentHash = migration.HashFiles(src.Files, src.Names)
	if _, err := runner.Apply(ctx, "materialize", src.ContentHash, src); err != nil {
		return nil, fmt.Errorf("apply DDL to scratch schema: %w", err)
	}

	snap, err = drift.NewInspector(devPool).Inspect(ctx, scratch)
	if err != nil {
		return nil, fmt.Errorf("inspect scratch schema: %w", err)
	}
	// The inspected snapshot embeds the throwaway scratch schema name in
	// its .Schema and in every catalog-derived DDL string (index/view/
	// function/policy definitions). Rewrite it to the caller's target
	// schema so the differ — which compares observed index DDL against
	// DDL it renders with the target schema — does not see the scratch
	// name as a spurious difference. The scratch name is a unique random
	// token, so a literal replacement cannot collide with real content.
	if targetSchema != "" && targetSchema != scratch {
		rewriteSnapshotSchema(snap, scratch, targetSchema)
	}
	return snap, nil
}

// rewriteSnapshotSchema replaces every occurrence of the schema name
// `from` with `to` across a snapshot's schema-qualified DDL strings.
// Safe because `from` is the unique scratch-schema token.
func rewriteSnapshotSchema(snap *drift.Snapshot, from, to string) {
	repl := func(s string) string { return strings.ReplaceAll(s, from, to) }
	snap.Schema = to

	// Extensions created by the desired source land in the scratch schema, so
	// their recorded namespace is the throwaway token. Left unrewritten it is
	// written verbatim into the authored migration as
	// CREATE EXTENSION ... SCHEMA "keystone_dev_<hash>".
	for i := range snap.Extensions {
		snap.Extensions[i].Schema = repl(snap.Extensions[i].Schema)
	}

	// format_type qualifies user-defined types with their schema, which is the
	// scratch name for anything the desired source created.
	for i := range snap.Tables {
		for j := range snap.Tables[i].Columns {
			snap.Tables[i].Columns[j].FormattedType = repl(snap.Tables[i].Columns[j].FormattedType)

			// A generation expression is stored fully qualified by PostgreSQL, so
			// every function and cast in it carries the scratch schema name. Here the
			// qualifier is REMOVED rather than rewritten to the target schema.
			//
			// Rewriting would bake in where the extension happened to live when the
			// migration was authored. Replaying that migration installs the extension
			// into a fresh scratch schema, and a hard-coded public.st_setsrid then
			// fails with 42704 type "public.geography" does not exist. Unqualified, it
			// resolves through the runner's search_path (target schema, then public)
			// in both cases.
			snap.Tables[i].Columns[j].Generated = strings.ReplaceAll(
				snap.Tables[i].Columns[j].Generated, from+".", "")

			// A DEFAULT is stored qualified for exactly the same reasons:
			// nextval('<schema>.seq'::regclass) for a serial-style column,
			// and '<label>'::<schema>.<enum> for an enum default. Left
			// alone, the scratch token is written straight into the
			// authored migration and the apply fails at the target with
			// 3F000 schema "keystone_dev_<hash>" does not exist — the
			// migration is broken before it is ever reviewed.
			//
			// Stripped rather than rewritten, matching Generated above: an
			// unqualified reference resolves through the runner's
			// search_path, so one bundle stays applicable to every schema
			// it fans out to instead of being pinned to whichever schema
			// happened to author it.
			snap.Tables[i].Columns[j].Default = strings.ReplaceAll(
				snap.Tables[i].Columns[j].Default, from+".", "")
		}
	}
	for i := range snap.Indexes {
		snap.Indexes[i].Definition = repl(snap.Indexes[i].Definition)
	}
	for i := range snap.Constraints {
		snap.Constraints[i].Definition = repl(snap.Constraints[i].Definition)
	}
	for i := range snap.Tables {
		snap.Tables[i].ViewDefinition = repl(snap.Tables[i].ViewDefinition)
	}
	for i := range snap.Functions {
		snap.Functions[i].Definition = repl(snap.Functions[i].Definition)
	}
	for i := range snap.Policies {
		snap.Policies[i].Using = repl(snap.Policies[i].Using)
		snap.Policies[i].WithCheck = repl(snap.Policies[i].WithCheck)
	}
	for i := range snap.MaterializedViews {
		snap.MaterializedViews[i].Definition = repl(snap.MaterializedViews[i].Definition)
	}
}

// scratchSchemaName returns a unique, identifier-valid scratch schema
// name. The random suffix avoids collisions between concurrent runs
// sharing one dev database.
func scratchSchemaName() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("scratch schema name: %w", err)
	}
	return "keystone_dev_" + hex.EncodeToString(b[:]), nil
}

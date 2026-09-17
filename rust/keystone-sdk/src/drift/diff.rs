// SPDX-License-Identifier: Apache-2.0

//! Structural drift between two snapshots.
//!
//! Ported from the Go `drift` package's `diff.go`. [`diff`] returns the
//! deltas between a baseline and an observed [`Snapshot`] as a stable,
//! deterministically-ordered list of [`DriftFinding`]s; [`severity`] grades
//! the list. Both functions reproduce the reference behaviour (finding kinds,
//! description strings, ordering, and the 128-item cap) exactly.
//!
//! The reference uses the operator's `keystonev1alpha1.DriftFinding` /
//! `DriftSeverity` CRD types; the equivalent shapes are defined here so the
//! SDK has no Kubernetes dependency.

use std::collections::BTreeMap;

use super::{ColumnShape, ObjectDdl, PolicyShape, Snapshot, TableShape};

/// One structural drift finding (mirrors `keystonev1alpha1.DriftFinding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftFinding {
    /// One of: `TableAdded`, `TableDropped`, `ColumnAdded`, `ColumnDropped`,
    /// `ColumnChanged`, `IndexAdded`, `IndexDropped`, `ConstraintAdded`,
    /// `ConstraintDropped`, `RLSEnabled`, `RLSDisabled`, `RLSForced`,
    /// `RLSUnforced`, `PolicyAdded`, `PolicyDropped`, `PolicyChanged`,
    /// `Other`.
    ///
    /// Must stay in step with the `Enum` marker on
    /// `keystonev1alpha1.DriftFinding.Kind`: an unlisted kind fails
    /// apiserver validation and takes the whole DriftReport patch with it.
    pub kind: String,
    /// Qualified PG object name (e.g. `crm.leads.score`).
    pub object: String,
    /// Human-readable detail.
    pub description: String,
}

/// Severity grade for a set of findings (mirrors `DriftSeverity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftSeverity {
    Info,
    Warning,
    Critical,
}

impl DriftSeverity {
    /// The wire string (`info`/`warning`/`critical`).
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftSeverity::Info => "info",
            DriftSeverity::Warning => "warning",
            DriftSeverity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returns the structural deltas between two snapshots. Both must be from
/// the same schema. Findings are returned in stable order so repeated diffs
/// of identical inputs produce identical output.
pub fn diff(baseline: &Snapshot, observed: &Snapshot) -> Vec<DriftFinding> {
    let mut out: Vec<DriftFinding> = Vec::new();

    // Tables: walk baseline (sorted), then walk observed for "added".
    let b_tables = tables_by_name(baseline);
    let o_tables = tables_by_name(observed);
    for (name, bt) in &b_tables {
        let Some(ot) = o_tables.get(name) else {
            out.push(DriftFinding {
                kind: "TableDropped".into(),
                object: format!("{}.{}", baseline.schema, name),
                description: format!("table existed in baseline ({}) but is absent now", bt.kind),
            });
            continue;
        };
        // Same name: compare columns.
        let bc = columns_by_name(&bt.columns);
        let oc = columns_by_name(&ot.columns);
        for (cn, bcol) in &bc {
            let Some(ocol) = oc.get(cn) else {
                out.push(DriftFinding {
                    kind: "ColumnDropped".into(),
                    object: format!("{}.{}.{}", baseline.schema, name, cn),
                    description: format!(
                        "column was {} NULL={} default={:?}",
                        bcol.data_type, bcol.nullable, bcol.default
                    ),
                });
                continue;
            };
            let changed = column_change(bcol, ocol);
            if !changed.is_empty() {
                out.push(DriftFinding {
                    kind: "ColumnChanged".into(),
                    object: format!("{}.{}.{}", baseline.schema, name, cn),
                    description: changed,
                });
            }
        }
        for (cn, ocol) in &oc {
            if bc.contains_key(cn) {
                continue;
            }
            out.push(DriftFinding {
                kind: "ColumnAdded".into(),
                object: format!("{}.{}.{}", baseline.schema, name, cn),
                description: format!(
                    "column added with {} NULL={} default={:?}",
                    ocol.data_type, ocol.nullable, ocol.default
                ),
            });
        }

        // RLS bits. Losing either one silently un-enforces every policy on
        // the table, so both directions are reported and the losing
        // direction is graded Critical by `severity`.
        rls_findings(&baseline.schema, name, bt, ot, &mut out);
    }
    for (name, ot) in &o_tables {
        if b_tables.contains_key(name) {
            continue;
        }
        out.push(DriftFinding {
            kind: "TableAdded".into(),
            object: format!("{}.{}", baseline.schema, name),
            description: format!(
                "table added ({}) with {} column(s)",
                ot.kind,
                ot.columns.len()
            ),
        });
    }

    // Indexes — keyed by (table, name).
    let b_idx = objects_by_key(&baseline.indexes);
    let o_idx = objects_by_key(&observed.indexes);
    for (k, v) in &b_idx {
        if !o_idx.contains_key(k) {
            out.push(DriftFinding {
                kind: "IndexDropped".into(),
                object: format!("{}.{}", baseline.schema, k),
                description: v.definition.clone(),
            });
        }
    }
    for (k, v) in &o_idx {
        if !b_idx.contains_key(k) {
            out.push(DriftFinding {
                kind: "IndexAdded".into(),
                object: format!("{}.{}", baseline.schema, k),
                description: v.definition.clone(),
            });
        }
    }

    // Constraints.
    let b_con = objects_by_key(&baseline.constraints);
    let o_con = objects_by_key(&observed.constraints);
    for (k, v) in &b_con {
        if !o_con.contains_key(k) {
            out.push(DriftFinding {
                kind: "ConstraintDropped".into(),
                object: format!("{}.{}", baseline.schema, k),
                description: format!("{}: {}", v.r#type, v.definition),
            });
        }
    }
    for (k, v) in &o_con {
        if !b_con.contains_key(k) {
            out.push(DriftFinding {
                kind: "ConstraintAdded".into(),
                object: format!("{}.{}", baseline.schema, k),
                description: format!("{}: {}", v.r#type, v.definition),
            });
        }
    }

    // Policies. Previously not compared at all, which made the report
    // actively misleading rather than merely incomplete: policies are part
    // of the Snapshot and therefore of `hash`, so dropping one DID trip
    // drift detection — and then attached a report with zero findings,
    // which `severity` graded Info.
    let b_pol = policies_by_key(&baseline.policies);
    let o_pol = policies_by_key(&observed.policies);
    for (k, bp) in &b_pol {
        match o_pol.get(k) {
            None => out.push(DriftFinding {
                kind: "PolicyDropped".into(),
                object: format!("{}.{}", baseline.schema, k),
                description: format!(
                    "policy on {} for {} was USING({})",
                    bp.table,
                    bp.command,
                    or_none(&bp.using)
                ),
            }),
            Some(op) => {
                let changed = policy_change(bp, op);
                if !changed.is_empty() {
                    out.push(DriftFinding {
                        kind: "PolicyChanged".into(),
                        object: format!("{}.{}", baseline.schema, k),
                        description: changed,
                    });
                }
            }
        }
    }
    for (k, op) in &o_pol {
        if !b_pol.contains_key(k) {
            out.push(DriftFinding {
                kind: "PolicyAdded".into(),
                object: format!("{}.{}", baseline.schema, k),
                description: format!(
                    "policy added on {} for {} USING({})",
                    op.table,
                    op.command,
                    or_none(&op.using)
                ),
            });
        }
    }

    // Cap — DriftReport schema enforces MaxItems=128; truncate so the
    // controller patch doesn't reject.
    //
    // Security findings are retained ahead of the rest: truncation is
    // positional and findings are emitted in object order, so a schema that
    // gained many objects in one pass could otherwise push a cross-tenant
    // exposure past the cap. The partition is stable, so repeated diffs of
    // identical input still produce identical output.
    if out.len() > 128 {
        partition_security_first(&mut out);
        let extra = out.len() - 127;
        out.truncate(127);
        out.push(DriftFinding {
            kind: "Other".into(),
            object: "(truncated)".into(),
            description: format!("{extra} additional findings omitted; inspect schema directly"),
        });
    }
    out
}

/// Compares the two row-level-security bits on one table.
///
/// Reported separately because they fail differently. Losing ENABLE turns
/// policies off for everyone. Losing FORCE turns them off only for the
/// table's owner — narrower-sounding and usually worse, because the owner is
/// typically the role the application connects as, so the policies remain
/// visibly present while enforcing nothing on the connection that matters.
fn rls_findings(
    schema: &str,
    table: &str,
    b: &TableShape,
    o: &TableShape,
    out: &mut Vec<DriftFinding>,
) {
    let object = format!("{schema}.{table}");
    if b.rls_enabled && !o.rls_enabled {
        out.push(DriftFinding {
            kind: "RLSDisabled".into(),
            object: object.clone(),
            description: "row-level security was ENABLED in baseline and is now DISABLED; every policy on this table is inert".into(),
        });
    } else if !b.rls_enabled && o.rls_enabled {
        out.push(DriftFinding {
            kind: "RLSEnabled".into(),
            object: object.clone(),
            description: "row-level security enabled (was disabled in baseline)".into(),
        });
    }
    // A baseline written before `rls_forced` existed cannot be compared on
    // it. Reporting the difference anyway would turn every already-forced
    // table into an "RLSForced was added" finding on the first reconcile
    // after the upgrade — and keep reporting it, because the stored baseline
    // is only rewritten when an operator accepts the drift. Callers that need
    // to tell a genuine change from the model change use
    // `Snapshot::predates_rls_force` and `Snapshot::without_rls_force`.
    let (Some(bf), Some(of)) = (b.rls_forced, o.rls_forced) else {
        return;
    };
    if bf && !of {
        out.push(DriftFinding {
            kind: "RLSUnforced".into(),
            object,
            description: "row-level security is no longer FORCED; policies are bypassed for the table owner, so an application connecting as the owner reads and writes across all rows regardless of policy".into(),
        });
    } else if !bf && of {
        out.push(DriftFinding {
            kind: "RLSForced".into(),
            object,
            description: "row-level security is now FORCED (applies to the table owner)".into(),
        });
    }
}

/// Findings describing a loss of enforcement rather than a change of shape.
/// These survive truncation and drive Critical.
fn is_security_kind(kind: &str) -> bool {
    matches!(
        kind,
        "RLSDisabled" | "RLSUnforced" | "PolicyDropped" | "PolicyChanged"
    )
}

/// Moves security findings to the front, preserving relative order within
/// both groups.
fn partition_security_first(findings: &mut Vec<DriftFinding>) {
    let mut sec: Vec<DriftFinding> = Vec::with_capacity(findings.len());
    let mut rest: Vec<DriftFinding> = Vec::with_capacity(findings.len());
    for f in findings.drain(..) {
        if is_security_kind(&f.kind) {
            sec.push(f);
        } else {
            rest.push(f);
        }
    }
    sec.append(&mut rest);
    *findings = sec;
}

fn policies_by_key(in_: &[PolicyShape]) -> BTreeMap<String, &PolicyShape> {
    in_.iter()
        .map(|p| (format!("{}.{}", p.table, p.name), p))
        .collect()
}

/// Describes how two same-named policies differ, or empty when equivalent.
/// The USING and WITH CHECK expressions are the enforcement itself, so a
/// rewrite is as significant as a drop.
fn policy_change(b: &PolicyShape, o: &PolicyShape) -> String {
    if b.using != o.using {
        return format!(
            "USING expression changed from ({}) to ({})",
            or_none(&b.using),
            or_none(&o.using)
        );
    }
    if b.with_check != o.with_check {
        return format!(
            "WITH CHECK expression changed from ({}) to ({})",
            or_none(&b.with_check),
            or_none(&o.with_check)
        );
    }
    if b.command != o.command {
        return format!("command changed from {} to {}", b.command, o.command);
    }
    if b.permissive != o.permissive {
        return format!(
            "changed from permissive={} to permissive={}",
            b.permissive, o.permissive
        );
    }
    if b.roles != o.roles {
        return format!("roles changed from {:?} to {:?}", b.roles, o.roles);
    }
    String::new()
}

fn or_none(s: &str) -> &str {
    if s.is_empty() {
        "none"
    } else {
        s
    }
}

/// Grades a slice of findings. Critical iff any `*Dropped` is present, or any
/// finding describes a loss of row-level-security enforcement; Warning if
/// anything else is in the list; Info if empty.
///
/// The enforcement-loss kinds are Critical for a different reason than the
/// `*Dropped` kinds. A dropped column is Critical because data is gone. A
/// table that is no longer FORCE-d has lost nothing visible — every row,
/// column and policy is still present and a shape comparison reads clean —
/// while having stopped isolating tenants from each other.
pub fn severity(findings: &[DriftFinding]) -> DriftSeverity {
    if findings.is_empty() {
        return DriftSeverity::Info;
    }
    for f in findings {
        match f.kind.as_str() {
            "TableDropped" | "ColumnDropped" | "IndexDropped" | "ConstraintDropped"
            | "RLSDisabled" | "RLSUnforced" | "PolicyDropped" | "PolicyChanged" => {
                return DriftSeverity::Critical
            }
            _ => {}
        }
    }
    DriftSeverity::Warning
}

/// Returns a non-empty description of the change, or empty if equivalent.
/// Compares the security-relevant fields only (ordinal swaps are ignored).
fn column_change(b: &ColumnShape, o: &ColumnShape) -> String {
    if b.data_type != o.data_type || b.udt_name != o.udt_name {
        return format!(
            "type {}→{} (udt {}→{})",
            b.data_type, o.data_type, b.udt_name, o.udt_name
        );
    }
    if b.nullable != o.nullable {
        return format!("nullability {}→{}", b.nullable, o.nullable);
    }
    if b.default != o.default {
        return format!("default {:?}→{:?}", b.default, o.default);
    }
    String::new()
}

// --- ordering helpers. BTreeMap gives the sorted iteration the Go helpers
// produce via sortStrings, so finding order matches the reference. ---

fn tables_by_name(s: &Snapshot) -> BTreeMap<&str, &TableShape> {
    s.tables.iter().map(|t| (t.name.as_str(), t)).collect()
}

fn columns_by_name(in_: &[ColumnShape]) -> BTreeMap<&str, &ColumnShape> {
    in_.iter().map(|c| (c.name.as_str(), c)).collect()
}

fn objects_by_key(in_: &[ObjectDdl]) -> BTreeMap<String, &ObjectDdl> {
    in_.iter()
        .map(|o| (format!("{}.{}", o.table, o.name), o))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, dt: &str, nullable: bool, default: &str) -> ColumnShape {
        ColumnShape {
            name: name.into(),
            ordinal: 1,
            data_type: dt.into(),
            udt_name: dt.into(),
            nullable,
            default: default.into(),
            ..Default::default()
        }
    }

    fn snap(schema: &str, tables: Vec<TableShape>) -> Snapshot {
        Snapshot {
            schema: schema.into(),
            tables,
            ..Default::default()
        }
    }

    #[test]
    fn empty_diff_is_info() {
        let a = snap("public", vec![]);
        let f = diff(&a, &a);
        assert!(f.is_empty());
        assert_eq!(severity(&f), DriftSeverity::Info);
    }

    #[test]
    fn table_dropped_is_critical() {
        let base = snap(
            "app",
            vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![col("id", "integer", false, "")],
                ..Default::default()
            }],
        );
        let obs = snap("app", vec![]);
        let f = diff(&base, &obs);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "TableDropped");
        assert_eq!(f[0].object, "app.users");
        assert_eq!(
            f[0].description,
            "table existed in baseline (BASE TABLE) but is absent now"
        );
        assert_eq!(severity(&f), DriftSeverity::Critical);
    }

    #[test]
    fn column_added_and_changed() {
        let base = snap(
            "app",
            vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![col("id", "integer", false, "")],
                ..Default::default()
            }],
        );
        let obs = snap(
            "app",
            vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![
                    col("id", "bigint", false, ""),
                    col("email", "text", true, "''::text"),
                ],
                ..Default::default()
            }],
        );
        let f = diff(&base, &obs);
        // Sorted by column name within table: "email" (added) before "id"
        // would NOT happen — changed "id" is emitted during the baseline
        // walk; "email" added during the observed walk. Order: id changed,
        // then email added.
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].kind, "ColumnChanged");
        assert_eq!(f[0].object, "app.users.id");
        assert_eq!(f[0].description, "type integer→bigint (udt integer→bigint)");
        assert_eq!(f[1].kind, "ColumnAdded");
        assert_eq!(f[1].object, "app.users.email");
        assert_eq!(
            f[1].description,
            "column added with text NULL=true default=\"''::text\""
        );
        assert_eq!(severity(&f), DriftSeverity::Warning);
    }

    #[test]
    fn truncates_over_128() {
        // 200 added tables → 128 findings, last is the truncation marker.
        let obs_tables: Vec<TableShape> = (0..200)
            .map(|i| TableShape {
                name: format!("t{i:03}"),
                kind: "BASE TABLE".into(),
                ..Default::default()
            })
            .collect();
        let f = diff(&snap("app", vec![]), &snap("app", obs_tables));
        assert_eq!(f.len(), 128);
        assert_eq!(f[127].kind, "Other");
        assert_eq!(f[127].object, "(truncated)");
        assert_eq!(
            f[127].description,
            "73 additional findings omitted; inspect schema directly"
        );
    }

    // --- RLS + policy drift (see TableShape::rls_forced) ---

    fn tenant_table(name: &str, enabled: bool, forced: bool) -> TableShape {
        TableShape {
            name: name.into(),
            kind: "BASE TABLE".into(),
            columns: vec![col("tenant_id", "uuid", false, "")],
            view_definition: String::new(),
            rls_enabled: enabled,
            rls_forced: Some(forced),
        }
    }

    fn isolation_policy(table: &str) -> PolicyShape {
        PolicyShape {
            name: "tenant_isolation".into(),
            table: table.into(),
            command: "ALL".into(),
            permissive: true,
            roles: vec!["public".into()],
            using: "(tenant_id = current_setting('app.current_tenant', true)::uuid)".into(),
            with_check: "(tenant_id = current_setting('app.current_tenant', true)::uuid)".into(),
        }
    }

    fn protected() -> Snapshot {
        Snapshot {
            schema: "public".into(),
            tables: vec![tenant_table("messages", true, true)],
            policies: vec![isolation_policy("messages")],
            ..Default::default()
        }
    }

    fn has_kind(f: &[DriftFinding], kind: &str) -> bool {
        f.iter().any(|x| x.kind == kind)
    }

    /// The regression that motivated tracking `relforcerowsecurity`: while
    /// the snapshot modelled only `relrowsecurity`, removing FORCE produced
    /// a byte-identical snapshot and therefore an identical hash, so the
    /// controller never even considered the schema drifted.
    #[test]
    fn hash_detects_unforced_rls() {
        let forced = protected();
        let mut unforced = protected();
        unforced.tables[0].rls_forced = Some(false);
        assert_ne!(
            super::super::hash(&forced).unwrap(),
            super::super::hash(&unforced).unwrap(),
            "losing owner-side RLS enforcement must change the snapshot hash"
        );
    }

    #[test]
    fn unforced_rls_is_critical() {
        let b = protected();
        let mut o = protected();
        o.tables[0].rls_forced = Some(false);
        let f = diff(&b, &o);
        assert!(has_kind(&f, "RLSUnforced"), "got {:?}", f);
        assert_eq!(severity(&f), DriftSeverity::Critical);
    }

    #[test]
    fn disabled_rls_is_critical() {
        let b = protected();
        let mut o = protected();
        o.tables[0].rls_enabled = false;
        o.tables[0].rls_forced = Some(false);
        let f = diff(&b, &o);
        assert!(has_kind(&f, "RLSDisabled"), "got {:?}", f);
        assert_eq!(severity(&f), DriftSeverity::Critical);
    }

    #[test]
    fn added_protection_is_only_a_warning() {
        let b = snap("public", vec![tenant_table("messages", false, false)]);
        let o = snap("public", vec![tenant_table("messages", true, true)]);
        let f = diff(&b, &o);
        assert!(
            has_kind(&f, "RLSEnabled") && has_kind(&f, "RLSForced"),
            "got {:?}",
            f
        );
        assert_eq!(severity(&f), DriftSeverity::Warning);
    }

    #[test]
    fn unchanged_rls_reports_nothing() {
        assert!(diff(&protected(), &protected()).is_empty());
    }

    /// Policies were hashed but never compared, so a dropped
    /// `tenant_isolation` tripped drift detection and then attached an empty
    /// finding list, which `severity` graded Info.
    #[test]
    fn dropped_policy_is_critical() {
        let b = protected();
        let mut o = protected();
        o.policies.clear();
        let f = diff(&b, &o);
        assert!(has_kind(&f, "PolicyDropped"), "got {:?}", f);
        assert_eq!(severity(&f), DriftSeverity::Critical);
    }

    #[test]
    fn rewritten_policy_is_critical() {
        let b = protected();
        let mut o = protected();
        o.policies[0].using = "true".into();
        let f = diff(&b, &o);
        assert!(has_kind(&f, "PolicyChanged"), "got {:?}", f);
        assert_eq!(severity(&f), DriftSeverity::Critical);
    }

    /// Policy names are unique per table, not per schema — two tables each
    /// carrying `tenant_isolation` must not collide in the comparison map.
    #[test]
    fn policies_are_keyed_by_table() {
        let b = Snapshot {
            schema: "public".into(),
            tables: vec![
                tenant_table("messages", true, true),
                tenant_table("mailboxes", true, true),
            ],
            policies: vec![isolation_policy("messages"), isolation_policy("mailboxes")],
            ..Default::default()
        };
        let o = Snapshot {
            schema: "public".into(),
            tables: vec![
                tenant_table("messages", true, true),
                tenant_table("mailboxes", true, true),
            ],
            policies: vec![isolation_policy("messages")],
            ..Default::default()
        };
        let f = diff(&b, &o);
        let dropped: Vec<&DriftFinding> = f.iter().filter(|x| x.kind == "PolicyDropped").collect();
        assert_eq!(dropped.len(), 1, "got {:?}", f);
        assert!(
            dropped[0].object.contains("mailboxes"),
            "got {:?}",
            dropped[0]
        );
    }

    /// Truncation is positional, so without the security partition a
    /// cross-tenant exposure could be pushed past the 128-item cap by a bulk
    /// of benign findings.
    #[test]
    fn security_findings_survive_truncation() {
        let mut b = snap("public", vec![tenant_table("zzz_last", true, true)]);
        let mut o = snap("public", vec![tenant_table("zzz_last", true, false)]);
        for i in 0..200 {
            o.tables
                .push(tenant_table(&format!("aaa_bulk_{i:03}"), false, false));
        }
        b.policies.clear();
        o.policies.clear();
        let f = diff(&b, &o);
        assert!(f.len() <= 128, "exceeded cap: {}", f.len());
        assert!(
            has_kind(&f, "RLSUnforced"),
            "security finding was truncated away"
        );
        assert_eq!(severity(&f), DriftSeverity::Critical);
    }

    #[test]
    fn diff_is_deterministic() {
        let b = protected();
        let mut o = protected();
        o.tables[0].rls_forced = Some(false);
        o.policies[0].using = "true".into();
        let first = diff(&b, &o);
        for _ in 0..5 {
            assert_eq!(first, diff(&b, &o));
        }
    }
}

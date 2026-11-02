// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
	"github.com/dogukanturhal/keystone-sdk/go/drift"
)

func matviewIndexFixture(def string) (*drift.Snapshot, *keystonev1alpha1.SchemaDefinitionSpec) {
	obs := &drift.Snapshot{
		Schema:            "public",
		MaterializedViews: []drift.MatViewShape{{Name: "mv_node_metrics", Definition: "SELECT 1;"}},
	}
	if def != "" {
		obs.Indexes = []drift.ObjectDDL{{
			Name: "idx_mv_node_metrics", Table: "mv_node_metrics", Type: "index", Definition: def,
		}}
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "public",
		MaterializedViews: []keystonev1alpha1.DesiredMaterializedView{{
			Name:  "mv_node_metrics",
			Query: "SELECT 1",
			Indexes: []keystonev1alpha1.DesiredIndex{{
				Name:    "idx_mv_node_metrics",
				Unique:  true,
				Columns: []string{"tenant_id", "workflow_definition_id", "node_id"},
			}},
		}},
	}
	return obs, desired
}

func TestDiff_MatViewIndex_MatchingLiveIsNoop(t *testing.T) {
	obs, desired := matviewIndexFixture(
		"CREATE UNIQUE INDEX idx_mv_node_metrics ON public.mv_node_metrics USING btree (tenant_id, workflow_definition_id, node_id)")
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) != 0 {
		t.Errorf("expected 0 operations, got %v", plan.Statements)
	}
}

func TestDiff_MatViewIndex_MissingEmitsOneCreate(t *testing.T) {
	obs, desired := matviewIndexFixture("")
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) != 1 || !strings.Contains(plan.Statements[0], "CREATE UNIQUE INDEX CONCURRENTLY") {
		t.Errorf("expected exactly one CREATE INDEX, got %v", plan.Statements)
	}
	if plan.DestructiveOps != 0 {
		t.Errorf("create must not be destructive, got %d", plan.DestructiveOps)
	}
}

func TestDiff_MatViewIndex_DifferingFollowsTablePolicy(t *testing.T) {
	obs, desired := matviewIndexFixture(
		"CREATE INDEX idx_mv_node_metrics ON public.mv_node_metrics USING btree (tenant_id)")

	// Same as table indexes: a changed definition needs a DROP, which
	// is refused unless allowDestructive is set.
	if _, err := Diff(obs, desired); err == nil || !strings.Contains(err.Error(), "destructive") {
		t.Fatalf("expected destructive refusal, got %v", err)
	}

	desired.AllowDestructive = true
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) != 2 ||
		!strings.Contains(plan.Statements[0], "DROP INDEX CONCURRENTLY IF EXISTS") ||
		!strings.Contains(plan.Statements[1], "CREATE UNIQUE INDEX CONCURRENTLY") {
		t.Errorf("expected DROP then CREATE, got %v", plan.Statements)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"testing"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestSequenceMatches_PGDefaultsBigint(t *testing.T) {
	// PG-canonical bigint ASC sequence with no user-specified bounds.
	observed := drift.SeqShape{
		Name: "s", DataType: "bigint", IncrementBy: 1,
		MinValue: 1, MaxValue: 9223372036854775807, StartValue: 1,
	}
	desired := keystonev1alpha1.DesiredSequence{
		Name: "s", DataType: "bigint", IncrementBy: 1,
		MinValue: 0, MaxValue: 0, StartWith: 0, // 0 = PG default
	}
	if !sequenceMatches(observed, "bigint", 1, desired) {
		t.Errorf("expected PG-default bigint sequence to match")
	}
}

func TestSequenceMatches_ExplicitBounds(t *testing.T) {
	observed := drift.SeqShape{
		Name: "s", DataType: "integer", IncrementBy: 1,
		MinValue: 1, MaxValue: 2147483647, StartValue: 100,
	}
	desired := keystonev1alpha1.DesiredSequence{
		Name: "s", DataType: "integer", IncrementBy: 1,
		MinValue: 0, MaxValue: 0, StartWith: 100,
	}
	if !sequenceMatches(observed, "integer", 1, desired) {
		t.Errorf("expected explicit StartWith=100 to match")
	}
}

func TestSequenceMatches_DataTypeMismatch(t *testing.T) {
	observed := drift.SeqShape{
		Name: "s", DataType: "integer", IncrementBy: 1,
		MinValue: 1, MaxValue: 2147483647, StartValue: 1,
	}
	desired := keystonev1alpha1.DesiredSequence{
		Name: "s", DataType: "bigint", IncrementBy: 1,
	}
	if sequenceMatches(observed, "bigint", 1, desired) {
		t.Errorf("integer vs bigint should not match")
	}
}

func TestSequenceMatches_IncrementMismatch(t *testing.T) {
	observed := drift.SeqShape{
		Name: "s", DataType: "bigint", IncrementBy: 1,
		MinValue: 1, MaxValue: 9223372036854775807, StartValue: 1,
	}
	desired := keystonev1alpha1.DesiredSequence{
		Name: "s", DataType: "bigint", IncrementBy: 2,
	}
	if sequenceMatches(observed, "bigint", 2, desired) {
		t.Errorf("inc 1 vs 2 should not match")
	}
}

func TestSequenceMatches_DataTypeCaseInsensitive(t *testing.T) {
	observed := drift.SeqShape{
		Name: "s", DataType: "BIGINT", IncrementBy: 1,
		MinValue: 1, MaxValue: 9223372036854775807, StartValue: 1,
	}
	desired := keystonev1alpha1.DesiredSequence{
		Name: "s", DataType: "bigint", IncrementBy: 1,
	}
	if !sequenceMatches(observed, "bigint", 1, desired) {
		t.Errorf("BIGINT vs bigint should match")
	}
}

func TestSequenceBoundEqual(t *testing.T) {
	cases := []struct {
		name              string
		observed, desired int64
		dataType, kind    string
		ascending         bool
		want              bool
	}{
		{"explicit-match", 100, 100, "integer", "start", true, true},
		{"explicit-mismatch", 100, 200, "integer", "start", true, false},
		{"default-min-asc-bigint", 1, 0, "bigint", "min", true, true},
		{"default-max-asc-bigint", 9223372036854775807, 0, "bigint", "max", true, true},
		{"default-max-asc-integer", 2147483647, 0, "integer", "max", true, true},
		{"non-default-observed-vs-default-desired", 50, 0, "integer", "start", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sequenceBoundEqual(c.observed, c.desired, c.dataType, c.kind, c.ascending); got != c.want {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

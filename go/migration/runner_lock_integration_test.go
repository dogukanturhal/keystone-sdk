// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package migration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dogukanturhal/keystone-sdk/go/internal/testdb"
)

func lockTestRunner(t *testing.T, schema string) *Runner {
	t.Helper()
	pool := testdb.Pool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schema))
	})
	r, err := NewRunner(pool, schema, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.EnsureBookkeeping(ctx); err != nil {
		t.Fatal(err)
	}
	return r
}

// Two concurrent Applies of CREATE TABLE on one schema: without the lock the
// loser fails 42P07 mid-flight; with it, the second observes the first's
// result only after it committed, so exactly one succeeds cleanly and the
// other fails (table exists) without ever overlapping.
func TestApplySerializesPerSchema(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"tx", "SELECT pg_sleep(0.5); CREATE TABLE t1 (id int);"},
		{"notx", "SELECT pg_sleep(0.5); CREATE TABLE t1 (id int); CREATE INDEX CONCURRENTLY i1 ON t1(id);"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := lockTestRunner(t, "lock_"+tc.name)
			var running, maxRunning int32
			r.Precheck = func(ctx context.Context) error {
				n := atomic.AddInt32(&running, 1)
				for {
					m := atomic.LoadInt32(&maxRunning)
					if n <= m || atomic.CompareAndSwapInt32(&maxRunning, m, n) {
						break
					}
				}
				time.Sleep(300 * time.Millisecond)
				atomic.AddInt32(&running, -1)
				return nil
			}
			src := &ResolvedSource{Names: []string{"001.sql"}, Files: map[string]string{"001.sql": tc.sql}}
			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i := range errs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = r.Apply(context.Background(), fmt.Sprintf("v%d", i), "h", src)
				}()
			}
			wg.Wait()
			if maxRunning != 1 {
				t.Fatalf("applies overlapped: max concurrent prechecks = %d", maxRunning)
			}
			ok := 0
			for _, e := range errs {
				if e == nil {
					ok++
				}
			}
			if ok != 1 {
				t.Fatalf("want exactly one success, got errs=%v", errs)
			}
		})
	}
}

func TestApplyPrecheckAborts(t *testing.T) {
	for _, sql := range []string{"CREATE TABLE t1 (id int);", "CREATE TABLE t1 (id int); CREATE INDEX CONCURRENTLY i1 ON t1(id);"} {
		r := lockTestRunner(t, "lock_pre")
		boom := errors.New("stale")
		r.Precheck = func(context.Context) error { return boom }
		src := &ResolvedSource{Names: []string{"001.sql"}, Files: map[string]string{"001.sql": sql}}
		_, err := r.Apply(context.Background(), "v1", "h", src)
		if !errors.Is(err, ErrPrecheckFailed) || !errors.Is(err, boom) {
			t.Fatalf("want ErrPrecheckFailed wrapping boom, got %v", err)
		}
		var n int
		if e := r.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM information_schema.tables WHERE table_schema='lock_pre' AND table_name='t1'`).Scan(&n); e != nil || n != 0 {
			t.Fatalf("SQL ran despite precheck abort (n=%d err=%v)", n, e)
		}
		applied, _, _ := r.IsApplied(context.Background(), "v1")
		if applied {
			t.Fatal("tracking row written despite abort")
		}
	}
}

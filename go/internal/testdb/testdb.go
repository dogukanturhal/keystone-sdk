// SPDX-License-Identifier: Apache-2.0

// Package testdb provides the dev database every integration suite in
// this module runs against.
//
// It exists so that "how do I get a PostgreSQL to test with" has exactly
// one answer. Each suite previously grew its own copy of the
// testcontainers boilerplate, which meant each also had to be taught
// separately how to run somewhere without a Docker daemon — and none of
// them were, so every integration suite in this module was dead in CI.
//
// Resolution order:
//
//  1. KEYSTONE_TEST_DSN — an already-running PostgreSQL. This is the CI
//     path: a GitLab `services:` container needs no Docker socket, which
//     the shared kubernetes executor does not provide.
//  2. testcontainers — the laptop path, when Docker is reachable.
//  3. skip — so `go test -tags integration ./...` stays usable with
//     neither. CI must therefore assert KEYSTONE_TEST_DSN is set before
//     running, because a suite that skips reports success.
//
// Internal by design: this is test scaffolding, not SDK surface.
package testdb

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// DSNEnv names an already-running PostgreSQL to test against.
const DSNEnv = "KEYSTONE_TEST_DSN"

// Image is the container started when no DSN is supplied. Pinned so a
// local run and a CI run exercise the same server version.
const Image = "postgres:16-alpine"

var (
	shared    *pgxpool.Pool
	sharedErr error
	// requested records that a DSN was named explicitly. When it was,
	// an unreachable database is a failure and not a reason to skip.
	requested bool
	once      sync.Once
)

// Pool returns the shared dev database, or skips the test when none is
// available.
//
// One pool is shared across every suite in a package run: starting a
// container costs seconds and the suites only ever touch throwaway
// scratch schemas, so there is nothing to isolate by paying that twice.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	once.Do(connect)
	if sharedErr != nil || shared == nil {
		// Asking for a specific database and not getting it is a failure.
		// Skipping there would reproduce exactly the hole this package was
		// written to close: CI sets the variable, the database is
		// unreachable, every suite skips, and the job reports success
		// having executed nothing. Only the "no database was requested at
		// all" case — a laptop with no Docker — is a legitimate skip.
		if requested {
			t.Fatalf("%s is set but unusable: %v", DSNEnv, sharedErr)
		}
		t.Skipf("no dev database: set %s, or start Docker for testcontainers (%v)", DSNEnv, sharedErr)
	}
	return shared
}

func connect() {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if dsn := os.Getenv(DSNEnv); dsn != "" {
		requested = true
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			sharedErr = fmt.Errorf("connect %s: %w", DSNEnv, err)
			return
		}
		if err := pool.Ping(ctx); err != nil {
			sharedErr = fmt.Errorf("ping %s: %w", DSNEnv, err)
			return
		}
		shared = pool
		return
	}

	c, err := tcpostgres.Run(ctx,
		Image,
		tcpostgres.WithUsername("keystone_sdk"),
		tcpostgres.WithPassword("test"),
		tcpostgres.WithDatabase("postgres"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		sharedErr = err
		return
	}
	host, err := c.Host(ctx)
	if err != nil {
		sharedErr = err
		return
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		sharedErr = err
		return
	}
	pool, err := pgxpool.New(ctx, fmt.Sprintf(
		"postgres://keystone_sdk:test@%s:%d/postgres?sslmode=disable", host, port.Num()))
	if err != nil {
		sharedErr = err
		return
	}
	shared = pool
}

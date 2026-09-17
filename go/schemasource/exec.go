// SPDX-License-Identifier: Apache-2.0

package schemasource

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultExecTimeout bounds how long an exec:// provider may run before
// it is killed. ORM providers shell out to a compiler toolchain
// (`dotnet build`, `go run`), so the budget is generous — but it is a
// budget, not an invitation to hang a CI job forever.
const DefaultExecTimeout = 5 * time.Minute

// maxExecOutput caps the DDL an exec:// provider may emit (16 MiB). A
// schema large enough to exceed this is a runaway provider, not a
// schema; failing loudly beats feeding a partial CREATE script into the
// dev database, where it would silently diff as "everything dropped".
const maxExecOutput = 16 << 20

// maxExecStderr bounds retained diagnostics. A provider that shells out to
// a compiler can be extremely chatty, and stderr is only ever rendered as
// its last few lines.
const maxExecStderr = 256 << 10

// runProgram executes an exec:// provider and returns its stdout as DDL.
//
// Contract with the provider (deliberately the same one Atlas's
// `external_schema` uses, so existing ORM providers port with a rename):
//
//   - stdout is the desired schema as PostgreSQL DDL, nothing else
//   - stderr is diagnostics, surfaced to the operator on failure
//   - a non-zero exit code means "I could not render the schema"
//
// stdin is closed rather than inherited: a provider that blocks reading
// stdin should fail fast, not deadlock a CI runner with no TTY.
func runProgram(ctx context.Context, program []string, dir string, env []string, timeout time.Duration) (string, error) {
	if len(program) == 0 {
		return "", fmt.Errorf("exec:// source has an empty program")
	}
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // G204: running an operator-supplied program is the
	// entire point of this scheme; it is gated by Resolver.AllowExec and
	// is never reachable from a cluster-supplied CR. See the package doc.
	cmd := exec.CommandContext(ctx, program[0], program[1:]...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = env
	}
	cmd.Stdin = nil

	stdout := &capped{limit: maxExecOutput}
	stderr := &capped{limit: maxExecStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("exec:// provider %q timed out after %s%s",
			strings.Join(program, " "), timeout, stderrTail(stderr))
	}
	if err != nil {
		return "", fmt.Errorf("exec:// provider %q failed: %w%s",
			strings.Join(program, " "), err, stderrTail(stderr))
	}
	if stdout.overflow {
		return "", fmt.Errorf("exec:// provider %q emitted more than the %d-byte limit; "+
			"a schema that large is a runaway provider, not a schema",
			strings.Join(program, " "), maxExecOutput)
	}

	ddl := stdout.buf.String()
	if strings.TrimSpace(ddl) == "" {
		return "", fmt.Errorf("exec:// provider %q emitted no DDL on stdout%s",
			strings.Join(program, " "), stderrTail(stderr))
	}
	return ddl, nil
}

// capped is an io.Writer that retains at most limit bytes and records
// whether more arrived.
//
// The point is to bound memory while the provider is still running.
// Buffering everything and checking the size afterwards enforces nothing:
// a provider emitting gigabytes exhausts the process before the check is
// ever reached.
//
// Writes past the limit are discarded but still reported as accepted, so
// the child is neither blocked nor killed by EPIPE — it runs to
// completion and the overflow is reported as a clean error rather than as
// a mysterious broken pipe from the provider's own perspective.
type capped struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (c *capped) Write(p []byte) (int, error) {
	if remaining := c.limit - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
			c.overflow = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.overflow = true
	}
	return len(p), nil
}

// stderrTail renders a provider's stderr for an error message, trimmed
// to the last few lines so a compiler's full output does not bury the
// one line that matters.
func stderrTail(c *capped) string {
	s := strings.TrimSpace(c.buf.String())
	if s == "" {
		return ""
	}
	if c.overflow {
		s += "\n… (stderr truncated)"
	}
	lines := strings.Split(s, "\n")
	const keep = 10
	if len(lines) > keep {
		lines = append([]string{"…"}, lines[len(lines)-keep:]...)
	}
	return "\nprovider stderr:\n  " + strings.Join(lines, "\n  ")
}

// SplitProgram splits a command line into argv the way a POSIX shell
// would for the simple cases, without invoking a shell.
//
// Not invoking a shell is the point: `exec://` takes a program and its
// arguments, so a reference can never smuggle in `; rm -rf /` or a pipe.
// Supported quoting is exactly what an ORM provider invocation needs:
//
//	dotnet keystone-ef                     → ["dotnet","keystone-ef"]
//	go run ./cmd/keystone-gorm             → ["go","run","./cmd/keystone-gorm"]
//	dotnet run --project "My App/App.csproj"
//	                                       → ["dotnet","run","--project","My App/App.csproj"]
//
// Single quotes are literal. Double quotes allow \" and \\ escapes.
// Anything a shell would do beyond that (globbing, variable expansion,
// redirection) is intentionally absent — use the program array form in
// keystone.yaml when the invocation is more complex than this.
func SplitProgram(s string) ([]string, error) {
	var (
		args    []string
		cur     strings.Builder
		started bool // distinguishes "" (a real empty arg) from no arg
	)
	const (
		bare = iota
		inSingle
		inDouble
	)
	state := bare

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch state {
		case bare:
			switch c {
			case ' ', '\t', '\n', '\r':
				if started {
					args = append(args, cur.String())
					cur.Reset()
					started = false
				}
			case '\'':
				state, started = inSingle, true
			case '"':
				state, started = inDouble, true
			case '\\':
				if i+1 >= len(s) {
					return nil, fmt.Errorf("trailing backslash in program %q", s)
				}
				i++
				cur.WriteByte(s[i])
				started = true
			default:
				cur.WriteByte(c)
				started = true
			}
		case inSingle:
			if c == '\'' {
				state = bare
				continue
			}
			cur.WriteByte(c)
		case inDouble:
			switch c {
			case '"':
				state = bare
			case '\\':
				if i+1 >= len(s) {
					return nil, fmt.Errorf("trailing backslash in program %q", s)
				}
				// Only \" and \\ are escapes inside double quotes; every
				// other backslash is literal, matching POSIX sh.
				if s[i+1] == '"' || s[i+1] == '\\' {
					i++
					cur.WriteByte(s[i])
				} else {
					cur.WriteByte(c)
				}
			default:
				cur.WriteByte(c)
			}
		}
	}
	if state != bare {
		return nil, fmt.Errorf("unterminated quote in program %q", s)
	}
	if started {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty program %q", s)
	}
	return args, nil
}

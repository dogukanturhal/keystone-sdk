// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"testing"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestNormaliseViewBody(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{
			name: "trailing-semicolon-stripped",
			a:    " SELECT id, name FROM users WHERE deleted_at IS NULL;",
			b:    "SELECT id, name FROM users WHERE deleted_at IS NULL",
			want: true,
		},
		{
			name: "quoted-identifiers-strip-equal",
			a:    `SELECT "id", "name" FROM "users"`,
			b:    `SELECT id, name FROM users`,
			want: true,
		},
		{
			name: "different-bodies-not-equal",
			a:    "SELECT id FROM users",
			b:    "SELECT name FROM users",
			want: false,
		},
		{
			name: "whitespace-irrelevant",
			a:    "SELECT id\n FROM\n  users",
			b:    "SELECT id FROM users",
			want: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normaliseViewBody(c.a) == normaliseViewBody(c.b)
			if got != c.want {
				t.Errorf("got %v want %v\n  norm(a)=%q\n  norm(b)=%q",
					got, c.want, normaliseViewBody(c.a), normaliseViewBody(c.b))
			}
		})
	}
}

func TestExtractFunctionBody(t *testing.T) {
	cases := []struct {
		name string
		def  string
		want string
	}{
		{
			name: "default-function-tag",
			def: `CREATE OR REPLACE FUNCTION public.f() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$function$
`,
			want: "BEGIN\n  NEW.updated_at := now();\n  RETURN NEW;\nEND;",
		},
		{
			name: "no-as-keyword-returns-input",
			def:  "not a function def",
			want: "not a function def",
		},
		{
			name: "alternate-tag",
			def: `CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $body$
BEGIN
  RAISE NOTICE 'hi';
END;
$body$`,
			want: "BEGIN\n  RAISE NOTICE 'hi';\nEND;",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractFunctionBody(c.def)
			if got != c.want {
				t.Errorf("\n got=%q\nwant=%q", got, c.want)
			}
		})
	}
}

func TestFunctionMatches(t *testing.T) {
	cases := []struct {
		name     string
		observed drift.FuncShape
		desired  keystonev1alpha1.DesiredFunction
		want     bool
	}{
		{
			name: "identical-body-different-dollar-quote",
			observed: drift.FuncShape{
				Name: "f", Args: "", Returns: "trigger", Language: "plpgsql",
				Definition: `CREATE OR REPLACE FUNCTION public.f() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$function$`,
			},
			desired: keystonev1alpha1.DesiredFunction{
				Name: "f", Args: "", Returns: "trigger", Language: "plpgsql",
				Body: "BEGIN\n  NEW.updated_at := now();\n  RETURN NEW;\nEND;",
			},
			want: true,
		},
		{
			name: "different-args-not-equal",
			observed: drift.FuncShape{
				Name: "f", Args: "id integer", Returns: "void", Language: "plpgsql",
				Definition: "CREATE FUNCTION f(id integer) RETURNS void LANGUAGE plpgsql AS $function$BEGIN END;$function$",
			},
			desired: keystonev1alpha1.DesiredFunction{
				Name: "f", Args: "id text", Returns: "void", Language: "plpgsql",
				Body: "BEGIN END;",
			},
			want: false,
		},
		{
			name: "language-case-insensitive",
			observed: drift.FuncShape{
				Name: "f", Args: "", Returns: "void", Language: "PLPGSQL",
				Definition: "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $function$BEGIN END;$function$",
			},
			desired: keystonev1alpha1.DesiredFunction{
				Name: "f", Args: "", Returns: "void", Language: "plpgsql",
				Body: "BEGIN END;",
			},
			want: true,
		},
		{
			name: "default-language-empty-equals-plpgsql",
			observed: drift.FuncShape{
				Name: "f", Args: "", Returns: "void", Language: "plpgsql",
				Definition: "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $function$BEGIN END;$function$",
			},
			desired: keystonev1alpha1.DesiredFunction{
				Name: "f", Args: "", Returns: "void", Language: "",
				Body: "BEGIN END;",
			},
			want: true,
		},
		{
			name: "different-body-not-equal",
			observed: drift.FuncShape{
				Name: "f", Args: "", Returns: "void", Language: "plpgsql",
				Definition: "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $function$BEGIN END;$function$",
			},
			desired: keystonev1alpha1.DesiredFunction{
				Name: "f", Args: "", Returns: "void", Language: "plpgsql",
				Body: "BEGIN RAISE NOTICE 'changed'; END;",
			},
			want: false,
		},
		{
			name: "whitespace-only-difference-equal",
			observed: drift.FuncShape{
				Name: "f", Args: "", Returns: "void", Language: "plpgsql",
				Definition: "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $function$BEGIN\n  IF x THEN\n    y := 1;\n  END IF;\nEND;$function$",
			},
			desired: keystonev1alpha1.DesiredFunction{
				Name: "f", Args: "", Returns: "void", Language: "plpgsql",
				Body: "BEGIN IF x THEN y := 1; END IF; END;",
			},
			want: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := functionMatches(c.observed, c.desired); got != c.want {
				t.Errorf("functionMatches() = %v, want %v", got, c.want)
			}
		})
	}
}

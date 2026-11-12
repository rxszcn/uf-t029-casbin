// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/util"
)

const patternIndexEffect = "some(where (p.eft == allow)) && !some(where (p.eft == deny))"

// newPatternIndexEnforcer builds an enforcer whose matcher compares p.obj
// with keyMatch, so the object field is a pattern rather than an equality
// key. The policies intentionally cover both decision-flip directions:
//
//   - a deny pattern "/data/*" that must keep overriding narrower allows;
//   - an allow pattern "/public/*" that must stay reachable for concrete
//     requests whose literal key differs from the pattern.
func newPatternIndexEnforcer(t testing.TB) *Enforcer {
	t.Helper()

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act, eft")
	m.AddDef("e", "e", patternIndexEffect)
	m.AddDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}

	rules := [][]string{
		{"alice", "/data/1", "read", "allow"},
		{"alice", "/data/*", "read", "deny"},
		{"bob", "/public/*", "read", "allow"},
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	return e
}

// newEqualityIndexEnforcer builds an enforcer whose matcher only uses the
// object field in an equality comparison, which is the partition-safe shape.
func newEqualityIndexEnforcer(t testing.TB) *Enforcer {
	t.Helper()

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act, eft")
	m.AddDef("e", "e", patternIndexEffect)
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}

	rules := [][]string{
		{"alice", "/data/1", "read", "allow"},
		{"alice", "/data/2", "read", "deny"},
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestSetPolicyIndexByTokenRejectsPatternMatcher verifies the install-time
// compatibility check: a token-based index on a field used in pattern
// matching must be refused instead of silently changing decisions.
func TestSetPolicyIndexByTokenRejectsPatternMatcher(t *testing.T) {
	e := newPatternIndexEnforcer(t)

	err := e.SetPolicyIndexByToken("p", "r_obj", "p_obj")
	if err == nil {
		t.Fatal("expected SetPolicyIndexByToken to reject a keyMatch matcher")
	}
	if !strings.Contains(err.Error(), "incompatible") || !strings.Contains(err.Error(), "p_obj") {
		t.Fatalf("error should name the incompatible token, got: %v", err)
	}
}

// TestPatternMatcherDecisionsStableWithoutIndex pins the baseline behavior
// that the index fallback must preserve.
func TestPatternMatcherDecisionsStableWithoutIndex(t *testing.T) {
	e := newPatternIndexEnforcer(t)

	cases := []struct {
		request []interface{}
		want    bool
	}{
		{[]interface{}{"alice", "/data/1", "read"}, false}, // deny pattern wins
		{[]interface{}{"alice", "/data/999", "read"}, false},
		{[]interface{}{"bob", "/public/chart.png", "read"}, true},
		{[]interface{}{"bob", "/private", "read"}, false},
	}
	for _, tc := range cases {
		got, err := e.Enforce(tc.request...)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%v: got %v, want %v", tc.request, got, tc.want)
		}
	}
}

// TestCustomIndexFallsBackForPatternKeys verifies the runtime conservative
// fallback: when a custom index partitions by a field that stores pattern
// values, enforcement must keep evaluating every rule so the decision matches
// the unindexed enforcer in both directions.
func TestCustomIndexFallsBackForPatternKeys(t *testing.T) {
	indexed := newPatternIndexEnforcer(t)
	if err := indexed.SetPolicyIndex("p", PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			return rvals[1].(string), true
		},
		PolicyKey: func(rule []string) string {
			return rule[1]
		},
	}); err != nil {
		t.Fatal(err)
	}

	unindexed := newPatternIndexEnforcer(t)

	cases := []struct {
		request []interface{}
		want    bool
	}{
		// The deny pattern "/data/*" lives in its own partition; without the
		// fallback it would be skipped and the request wrongly allowed.
		{[]interface{}{"alice", "/data/999", "read"}, false},
		{[]interface{}{"alice", "/data/1", "read"}, false},
		// The allow pattern "/public/*" must keep matching requests whose
		// literal key is not "/public/*".
		{[]interface{}{"bob", "/public/chart.png", "read"}, true},
		{[]interface{}{"bob", "/private", "read"}, false},
	}
	for _, tc := range cases {
		got, err := indexed.Enforce(tc.request...)
		if err != nil {
			t.Fatal(err)
		}
		want, err := unindexed.Enforce(tc.request...)
		if err != nil {
			t.Fatal(err)
		}
		if got != want || got != tc.want {
			t.Fatalf("%v: indexed=%v unindexed=%v want=%v", tc.request, got, want, tc.want)
		}
	}
}

// TestRuntimeFallbackRecoversWhenPatternRemoved verifies that the fallback is
// tied to the current policy contents rather than latched forever: once the
// pattern rules are gone the index prunes partitions again.
func TestRuntimeFallbackRecoversWhenPatternRemoved(t *testing.T) {
	e, calls := newPatternCallCounterEnforcer(t)
	if err := e.SetPolicyIndex("p", PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			return rvals[1].(string), true
		},
		PolicyKey: func(rule []string) string {
			return rule[1]
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Pattern keys present: the fallback evaluates every rule, so the probe
	// runs once per rule even though no rule matches the request.
	*calls = 0
	if ok, err := e.Enforce("nobody", "/nothing", "read"); err != nil || ok {
		t.Fatalf("with pattern: ok=%v err=%v, want deny", ok, err)
	}
	if *calls != 3 {
		t.Fatalf("with pattern: evaluated %d rules, want full scan of 3", *calls)
	}

	// Replace every pattern-shaped key with literal ones; the index becomes
	// partition-safe again.
	if _, err := e.RemovePolicy("alice", "/data/*", "read", "deny"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RemovePolicy("bob", "/public/*", "read", "allow"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("alice", "/data/2", "read", "allow"); err != nil {
		t.Fatal(err)
	}

	*calls = 0
	if ok, err := e.Enforce("alice", "/data/2", "read"); err != nil || !ok {
		t.Fatalf("after patterns removed: ok=%v err=%v, want allow", ok, err)
	}
	// Only the "/data/2" partition is evaluated; "/data/1" is pruned.
	if *calls != 1 {
		t.Fatalf("after patterns removed: evaluated %d rules, want 1 (partition pruned)", *calls)
	}
}

// newPatternCallCounterEnforcer mirrors newPatternIndexEnforcer but counts
// how many rules the matcher actually evaluates. The probe is placed first in
// the conjunction so it runs for every evaluated rule regardless of
// short-circuiting in later terms.
func newPatternCallCounterEnforcer(t testing.TB) (*Enforcer, *int) {
	t.Helper()

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act, eft")
	m.AddDef("e", "e", patternIndexEffect)
	m.AddDef("m", "m", "probe() && r.sub == p.sub && countedKeyMatch(r.obj, p.obj) && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	e.AddFunction("probe", func(args ...interface{}) (interface{}, error) {
		calls++
		return true, nil
	})
	e.AddFunction("countedKeyMatch", func(args ...interface{}) (interface{}, error) {
		return util.KeyMatch(args[0].(string), args[1].(string)), nil
	})

	rules := [][]string{
		{"alice", "/data/1", "read", "allow"},
		{"alice", "/data/*", "read", "deny"},
		{"bob", "/public/*", "read", "allow"},
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	return e, &calls
}

// TestEqualityMatcherAcceptsTokenIndexAndPrunes verifies the happy path of the
// install-time check: a pure equality matcher is accepted and the index still
// prunes unrelated partitions.
func TestEqualityMatcherAcceptsTokenIndexAndPrunes(t *testing.T) {
	e := newEqualityIndexEnforcer(t)
	if err := e.SetPolicyIndexByToken("p", "r_obj", "p_obj"); err != nil {
		t.Fatalf("equality matcher should be accepted: %v", err)
	}

	if ok, err := e.Enforce("alice", "/data/1", "read"); err != nil || !ok {
		t.Fatalf("/data/1: ok=%v err=%v, want allow", ok, err)
	}
	if ok, err := e.Enforce("alice", "/data/2", "read"); err != nil || ok {
		t.Fatalf("/data/2: ok=%v err=%v, want deny", ok, err)
	}
	if ok, err := e.Enforce("alice", "/missing", "read"); err != nil || ok {
		t.Fatalf("/missing: ok=%v err=%v, want deny", ok, err)
	}
}

// TestInstallTimeCheckRejectsUnsafeMatcherShapes enumerates the matcher shapes
// that must not be combined with a token-based partition on p.obj.
func TestInstallTimeCheckRejectsUnsafeMatcherShapes(t *testing.T) {
	unsafeMatchers := map[string]string{
		"regex comparator":      "r.sub == p.sub && r.obj =~ p.obj",
		"inequality":            "r.sub == p.sub && r.obj != p.obj",
		"ordering":              "r.sub == p.sub && r.obj < p.obj",
		"regexMatch function":   "r.sub == p.sub && regexMatch(r.obj, p.obj)",
		"globMatch function":    "r.sub == p.sub && globMatch(r.obj, p.obj)",
		"ipMatch function":      "r.sub == p.sub && ipMatch(r.obj, p.obj)",
		"eval on policy token":  "r.sub == p.sub && eval(p.obj)",
		"in comparator":         "r.sub == p.sub && p.obj in (r.obj, r.act)",
		"ternary on policy":     "r.sub == p.sub && (r.obj == p.obj ? true : p.obj == '*')",
		"token unused":          "r.sub == p.sub && r.act == p.act",
	}

	for name, matcher := range unsafeMatchers {
		t.Run(name, func(t *testing.T) {
			m := model.NewModel()
			m.AddDef("r", "r", "sub, obj, act")
			m.AddDef("p", "p", "sub, obj, act, eft")
			m.AddDef("e", "e", patternIndexEffect)
			m.AddDef("m", "m", matcher)

			e, err := NewEnforcer(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.SetPolicyIndexByToken("p", "r_obj", "p_obj"); err == nil {
				t.Fatalf("matcher %q must be rejected", matcher)
			}
		})
	}
}

// TestInstallTimeCheckAcceptsSafeMatcherShapes covers the equality and
// wildcard-literal shapes that the partition invariant relies on.
func TestInstallTimeCheckAcceptsSafeMatcherShapes(t *testing.T) {
	safeMatchers := []string{
		"r.sub == p.sub && r.obj == p.obj && r.act == p.act",
		"r.sub == p.sub && (r.obj == p.obj || p.obj == '*')",
		"r.sub == p.sub && ('*' == p.obj || p.obj == r.obj)",
	}

	for _, matcher := range safeMatchers {
		m := model.NewModel()
		m.AddDef("r", "r", "sub, obj, act")
		m.AddDef("p", "p", "sub, obj, act, eft")
		m.AddDef("e", "e", patternIndexEffect)
		m.AddDef("m", "m", matcher)

		e, err := NewEnforcer(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.SetPolicyIndexByToken("p", "r_obj", "p_obj"); err != nil {
			t.Fatalf("matcher %q should be accepted: %v", matcher, err)
		}
	}
}

// TestInstallTimeChecksEveryMatcher ensures an additional matcher that uses
// the indexed token unsafely is rejected even when the default matcher is
// safe, since EnforceWithMatcher can select it at runtime.
func TestInstallTimeChecksEveryMatcher(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act, eft")
	m.AddDef("e", "e", patternIndexEffect)
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	m.AddDef("m", "m2", "r.sub == p.sub && keyMatch(r.obj, p.obj)")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetPolicyIndexByToken("p", "r_obj", "p_obj"); err == nil {
		t.Fatal("expected rejection because matcher m2 uses keyMatch on p_obj")
	}
}

// TestRuntimeFallbackCoversCustomMatcher verifies that a runtime matcher
// supplied through EnforceWithMatcher cannot bypass the protection: the
// pattern-key fallback keeps the decision identical to the unindexed one.
func TestRuntimeFallbackCoversCustomMatcher(t *testing.T) {
	indexed := newPatternIndexEnforcer(t)
	// Install an index declared on the equality shape, then enforce with a
	// different matcher that pattern-matches the same field. The stored
	// pattern keys still force a full scan.
	if err := indexed.SetPolicyIndex("p", PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			return rvals[1].(string), true
		},
		PolicyKey: func(rule []string) string {
			return rule[1]
		},
	}); err != nil {
		t.Fatal(err)
	}

	const patternMatcher = "r.sub == p.sub && keyMatch(r.obj, p.obj) && r.act == p.act"
	unindexed := newPatternIndexEnforcer(t)

	cases := [][]interface{}{
		{"alice", "/data/999", "read"},
		{"alice", "/data/1", "read"},
		{"bob", "/public/chart.png", "read"},
	}
	for _, request := range cases {
		got, err := indexed.EnforceWithMatcher(patternMatcher, request...)
		if err != nil {
			t.Fatal(err)
		}
		want, err := unindexed.EnforceWithMatcher(patternMatcher, request...)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%v: indexed=%v unindexed=%v", request, got, want)
		}
	}
}

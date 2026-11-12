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
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/casbin/govaluate"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/util"
)

const (
	wildcardPolicyBucket uint32 = ^uint32(0)
	missingPolicyBucket  uint32 = ^uint32(1)
)

// patternMetaChars are the characters that turn a literal partition key into
// a glob/regex style pattern for the built-in pattern matchers (keyMatch*,
// regexMatch, globMatch, ipMatch, ...). A key carrying any of them only
// matches its literal partition by accident, so the index must fall back to a
// full scan rather than silently skipping rules.
const patternMetaChars = `*?{}[]:()|\^$.+`

// PolicyIndex partitions the policy rules of one policy type so that Enforce
// only evaluates the rules in the request's partition.
//
// RequestKey receives the request values, with an optional EnforceContext
// removed, and returns the partition key for the request. Returning false
// disables the index for that request, so every rule is evaluated.
//
// PolicyKey returns the partition key for one policy rule. The key "*" puts
// the rule in every partition.
//
// Enforce skips the matcher of a rule whose key differs from the request key.
// The caller must guarantee that such a rule can never match the request;
// otherwise the decision changes. This includes matchers that evaluate policy
// fields with eval(). Rules are still merged by the configured effector, so
// deny rules must be reachable through the request key or "*".
//
// SetPolicyIndex rejects an index whose policy token participates in pattern
// matching or any other non-equality comparison in the model matcher, and
// Enforce falls back to evaluating every rule when a stored rule key looks
// like a pattern. Together these keep the indexed decision identical to the
// unindexed one.
type PolicyIndex struct {
	RequestKey func(rvals []interface{}) (string, bool)
	PolicyKey  func(rule []string) string
}

// SetPolicyIndex installs a policy partition for ptype. It replaces an
// existing index for the same policy type. The index is rebuilt automatically
// when the policy changes.
//
// When policyToken is non-empty, the model matcher is statically checked: the
// indexed policy token may only appear in equality comparisons against the
// matching request token or the literal "*". Pattern functions (keyMatch,
// regexMatch, ...), eval() and other non-equality uses make partitioning
// unsafe and are rejected with an error, because installing the index would
// otherwise change enforcement decisions. Pass an empty policyToken for a
// fully custom index whose key contract the caller vouches for; the runtime
// pattern-key fallback still applies.
func (e *Enforcer) SetPolicyIndex(ptype string, index PolicyIndex, policyToken ...string) error {
	if index.RequestKey == nil || index.PolicyKey == nil {
		return errors.New("policy index functions cannot be nil")
	}
	pAssertion, ok := e.model["p"][ptype]
	if !ok {
		return fmt.Errorf("policy type %q does not exist", ptype)
	}

	var tokenName string
	if len(policyToken) > 0 && policyToken[0] != "" {
		tokenName = policyToken[0]
		if err := e.validateIndexMatcher(ptype, pAssertion, tokenName); err != nil {
			return err
		}
	}

	e.policyIndexes.Store(ptype, &policyIndex{
		requestKey: index.RequestKey,
		policyKey:  index.PolicyKey,
	})
	return nil
}

// validateIndexMatcher parses every matcher that can be combined with ptype
// and rejects those in which policyToken is used in a non partition-safe way.
func (e *Enforcer) validateIndexMatcher(ptype string, pAssertion *model.Assertion, policyToken string) error {
	requestToken, err := e.requestTokenFor(pAssertion, policyToken)
	if err != nil {
		return err
	}

	escapedPolicyToken := util.EscapeAssertion(policyToken)
	escapedRequestToken := ""
	if requestToken != "" {
		escapedRequestToken = util.EscapeAssertion(requestToken)
	}

	functions := e.matcherFunctions()
	for mName, mAssertion := range e.model["m"] {
		rawMatcher := util.RemoveComments(mAssertion.Value)
		root, parseErr := parseMatcher(util.EscapeAssertion(rawMatcher), functions)
		if parseErr != nil {
			return fmt.Errorf("cannot verify policy index against matcher %q: %w", mName, parseErr)
		}
		if checkErr := checkIndexCompatibility(root, escapedPolicyToken, escapedRequestToken); checkErr != nil {
			return fmt.Errorf("policy index on %q is incompatible with matcher %q: %w",
				ptype, mName, checkErr)
		}
	}
	return nil
}

// matcherFunctions assembles the same function table Enforce uses: built-in
// and user functions plus the g() closure for every role definition.
func (e *Enforcer) matcherFunctions() map[string]govaluate.ExpressionFunction {
	functions := e.fm.GetFunctions()
	if gSection, ok := e.model["g"]; ok {
		for key, ast := range gSection {
			switch {
			case ast.RM != nil:
				functions[key] = util.GenerateGFunction(ast.RM, e.gFunctionCache)
			case ast.CondRM != nil:
				functions[key] = util.GenerateConditionalGFunction(ast.CondRM)
			}
		}
	}
	return functions
}

// requestTokenFor maps a policy token to the corresponding request token by
// position in the token lists, e.g. p_obj -> r_obj. An empty result means no
// positional counterpart exists; the equality check then only allows the
// wildcard literal form.
func (e *Enforcer) requestTokenFor(pAssertion *model.Assertion, policyToken string) (string, error) {
	pos := -1
	for i, token := range pAssertion.Tokens {
		if token == policyToken {
			pos = i
			break
		}
	}
	if pos < 0 {
		return "", fmt.Errorf("policy token %q does not exist", policyToken)
	}

	rAssertion, ok := e.model["r"]["r"]
	if !ok {
		return "", nil
	}
	if pos >= len(rAssertion.Tokens) {
		return "", nil
	}
	return rAssertion.Tokens[pos], nil
}

// SetPolicyIndexByToken installs a policy partition that uses the string value
// of requestToken as the request key and the string value of policyToken as
// the rule key. It uses the default request type "r"; use SetPolicyIndex with
// a custom function when enforcing through an EnforceContext.
func (e *Enforcer) SetPolicyIndexByToken(ptype string, requestToken string, policyToken string) error {
	rAssertion, ok := e.model["r"]["r"]
	if !ok {
		return errors.New("request type \"r\" does not exist")
	}
	requestIndex := -1
	for i, token := range rAssertion.Tokens {
		if token == requestToken {
			requestIndex = i
			break
		}
	}
	if requestIndex == -1 {
		return fmt.Errorf("request token %q does not exist", requestToken)
	}

	pAssertion, ok := e.model["p"][ptype]
	if !ok {
		return fmt.Errorf("policy type %q does not exist", ptype)
	}
	policyIndex := -1
	for i, token := range pAssertion.Tokens {
		if token == policyToken {
			policyIndex = i
			break
		}
	}
	if policyIndex == -1 {
		return fmt.Errorf("policy token %q does not exist", policyToken)
	}

	return e.SetPolicyIndex(ptype, PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			if requestIndex >= len(rvals) {
				return "", false
			}
			key, ok := rvals[requestIndex].(string)
			return key, ok
		},
		PolicyKey: func(rule []string) string {
			if policyIndex >= len(rule) {
				return ""
			}
			return rule[policyIndex]
		},
	}, policyToken)
}

// RemovePolicyIndex removes the policy partition for ptype.
func (e *Enforcer) RemovePolicyIndex(ptype string) {
	e.policyIndexes.Delete(ptype)
}

func (e *Enforcer) getPolicyIndex(ptype string) *policyIndex {
	if value, ok := e.policyIndexes.Load(ptype); ok {
		return value.(*policyIndex)
	}
	return nil
}

type policyIndex struct {
	requestKey func(rvals []interface{}) (string, bool)
	policyKey  func(rule []string) string

	mu        sync.Mutex
	built     bool
	version   uint64
	bucketIDs []uint32
	names     map[string]uint32
	// patternKey is set when at least one non-wildcard rule key carries
	// pattern metacharacters. The partition then cannot guarantee that a
	// rule in another bucket can never match, so enforcement conservatively
	// evaluates every rule (full scan) until the pattern is removed.
	patternKey bool
}

func (idx *policyIndex) ensureBuilt(ast *model.Assertion) []uint32 {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.built && idx.version == ast.PolicyVersion && len(idx.bucketIDs) == len(ast.Policy) {
		return idx.bucketIDs
	}

	names := make(map[string]uint32)
	bucketIDs := make([]uint32, len(ast.Policy))
	var next uint32
	patternKey := false
	for i, rule := range ast.Policy {
		key := idx.policyKey(rule)
		if key == "*" {
			bucketIDs[i] = wildcardPolicyBucket
			continue
		}

		if containsPatternMeta(key) {
			patternKey = true
		}

		id, ok := names[key]
		if !ok {
			id = next
			names[key] = id
			next++
		}
		bucketIDs[i] = id
	}

	idx.version = ast.PolicyVersion
	idx.bucketIDs = bucketIDs
	idx.names = names
	idx.patternKey = patternKey
	idx.built = true
	return bucketIDs
}

// containsPatternMeta reports whether key holds characters that the built-in
// pattern matchers treat as glob/regex syntax rather than literal text.
func containsPatternMeta(key string) bool {
	for i := 0; i < len(key); i++ {
		if strings.IndexByte(patternMetaChars, key[i]) >= 0 {
			return true
		}
	}
	return false
}

func (idx *policyIndex) reset() {
	idx.mu.Lock()
	idx.built = false
	idx.bucketIDs = nil
	idx.names = nil
	idx.patternKey = false
	idx.mu.Unlock()
}

// usable reports whether the partition may prune rules for this build. A
// pattern-shaped key disables pruning even when the matcher passed the
// install-time check, covering custom PolicyKey functions and matchers
// installed after the index.
func (idx *policyIndex) usable() bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return idx.built && !idx.patternKey
}

func (idx *policyIndex) requestBucket(rvals []interface{}) (uint32, bool) {
	key, ok := idx.requestKey(rvals)
	if !ok {
		return 0, false
	}

	idx.mu.Lock()
	id, found := idx.names[key]
	idx.mu.Unlock()
	if !found {
		return missingPolicyBucket, true
	}
	return id, true
}

func policyMatchesBucket(bucketIDs []uint32, policyIndex int, bucket uint32) bool {
	if policyIndex < 0 || policyIndex >= len(bucketIDs) {
		return true
	}
	id := bucketIDs[policyIndex]
	return id == wildcardPolicyBucket || id == bucket
}

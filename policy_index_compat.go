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
	"fmt"
	"strings"

	"github.com/casbin/govaluate"
)

// matcherNode is a minimal syntax tree reconstructed from the infix token
// stream of a govaluate expression. It records only what the policy-index
// compatibility check needs.
type matcherNode struct {
	kind nodeKind

	// token carries the raw token text: a variable name, a literal or an
	// operator symbol.
	token string

	// fn is set for kind == nodeFunction.
	fn string
	// args holds function arguments, or the operands of an operator.
	args []*matcherNode
}

type nodeKind int

const (
	nodeLiteral nodeKind = iota
	nodeVariable
	nodeFunction
	nodeUnary
	nodeBinary
	nodeTernary
)

// tokenParser walks one govaluate infix token stream.
type tokenParser struct {
	tokens []govaluate.ExpressionToken
	pos    int
}

func (p *tokenParser) peek() (govaluate.ExpressionToken, bool) {
	if p.pos >= len(p.tokens) {
		return govaluate.ExpressionToken{}, false
	}
	return p.tokens[p.pos], true
}

func (p *tokenParser) next() govaluate.ExpressionToken {
	tk := p.tokens[p.pos]
	p.pos++
	return tk
}

// parseExpression parses a full comma-free expression.
func (p *tokenParser) parseExpression() (*matcherNode, error) {
	return p.parseTernary()
}

func (p *tokenParser) parseTernary() (*matcherNode, error) {
	cond, err := p.parseLogicalOr()
	if err != nil {
		return nil, err
	}

	tk, ok := p.peek()
	if !ok || tk.Kind != govaluate.TERNARY || tk.Value.(string) != "?" {
		return cond, nil
	}
	p.next()

	yes, err := p.parseTernary()
	if err != nil {
		return nil, err
	}

	tk, ok = p.peek()
	if !ok || tk.Kind != govaluate.TERNARY || tk.Value.(string) != ":" {
		return nil, fmt.Errorf("expected ':' in ternary expression")
	}
	p.next()

	no, err := p.parseTernary()
	if err != nil {
		return nil, err
	}

	return &matcherNode{kind: nodeTernary, token: "?:", args: []*matcherNode{cond, yes, no}}, nil
}

func (p *tokenParser) parseLogicalOr() (*matcherNode, error) {
	left, err := p.parseLogicalAnd()
	if err != nil {
		return nil, err
	}
	for {
		tk, ok := p.peek()
		if !ok || tk.Kind != govaluate.LOGICALOP || tk.Value.(string) != "||" {
			return left, nil
		}
		p.next()
		right, err := p.parseLogicalAnd()
		if err != nil {
			return nil, err
		}
		left = &matcherNode{kind: nodeBinary, token: "||", args: []*matcherNode{left, right}}
	}
}

func (p *tokenParser) parseLogicalAnd() (*matcherNode, error) {
	left, err := p.parseComparator()
	if err != nil {
		return nil, err
	}
	for {
		tk, ok := p.peek()
		if !ok || tk.Kind != govaluate.LOGICALOP || tk.Value.(string) != "&&" {
			return left, nil
		}
		p.next()
		right, err := p.parseComparator()
		if err != nil {
			return nil, err
		}
		left = &matcherNode{kind: nodeBinary, token: "&&", args: []*matcherNode{left, right}}
	}
}

// parseComparator covers every non-logical binary operator. govaluate emits
// "in" and the regex operators as COMPARATOR tokens, so a single level is
// enough: the check rejects every comparator except "==" anyway, so operator
// precedence inside an unsafe subexpression does not matter.
func (p *tokenParser) parseComparator() (*matcherNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		tk, ok := p.peek()
		if !ok || tk.Kind != govaluate.COMPARATOR {
			return left, nil
		}
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &matcherNode{kind: nodeBinary, token: tk.Value.(string), args: []*matcherNode{left, right}}
	}
}

func (p *tokenParser) parseUnary() (*matcherNode, error) {
	tk, ok := p.peek()
	if ok && tk.Kind == govaluate.PREFIX {
		p.next()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &matcherNode{kind: nodeUnary, token: tk.Value.(string), args: []*matcherNode{operand}}, nil
	}
	return p.parsePrimary()
}

func (p *tokenParser) parsePrimary() (*matcherNode, error) {
	tk, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of matcher")
	}

	switch tk.Kind {
	case govaluate.CLAUSE:
		p.next()
		node, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		closeToken, ok := p.peek()
		if !ok || closeToken.Kind != govaluate.CLAUSE_CLOSE {
			return nil, fmt.Errorf("unbalanced parenthesis in matcher")
		}
		p.next()
		return node, nil

	case govaluate.FUNCTION:
		return p.parseFunction()

	case govaluate.VARIABLE:
		p.next()
		return &matcherNode{kind: nodeVariable, token: tk.Value.(string)}, nil

	case govaluate.STRING, govaluate.NUMERIC, govaluate.BOOLEAN,
		govaluate.TIME, govaluate.PATTERN:
		p.next()
		return &matcherNode{kind: nodeLiteral, token: fmt.Sprintf("%v", tk.Value)}, nil

	default:
		return nil, fmt.Errorf("unsupported matcher token %v", tk.Kind)
	}
}

func (p *tokenParser) parseFunction() (*matcherNode, error) {
	fnToken := p.next()

	open, ok := p.peek()
	if !ok || open.Kind != govaluate.CLAUSE {
		return nil, fmt.Errorf("function call is not followed by an argument list")
	}
	p.next()

	node := &matcherNode{kind: nodeFunction, fn: fnToken.Value.(string)}
	if closeToken, ok := p.peek(); ok && closeToken.Kind == govaluate.CLAUSE_CLOSE {
		p.next()
		return node, nil
	}

	for {
		arg, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		node.args = append(node.args, arg)

		sep, ok := p.peek()
		if !ok {
			return nil, fmt.Errorf("unbalanced argument list of function %q", node.fn)
		}
		switch sep.Kind {
		case govaluate.SEPARATOR:
			p.next()
			continue
		case govaluate.CLAUSE_CLOSE:
			p.next()
			return node, nil
		default:
			return nil, fmt.Errorf("unexpected token in argument list of function %q", node.fn)
		}
	}
}

// parseMatcher builds the syntax tree of an escaped matcher expression.
// govaluate FUNCTION tokens hold the compiled closure rather than the
// function name, so function names are recovered from the raw matcher text
// (calls and FUNCTION tokens appear in the same order) and stamped onto the
// tokens before parsing.
func parseMatcher(rawMatcher string, functions map[string]govaluate.ExpressionFunction) (*matcherNode, error) {
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(rawMatcher, functions)
	if err != nil {
		return nil, err
	}
	tokens := stampFunctionNames(expression.Tokens(), rawMatcher)

	parser := &tokenParser{tokens: tokens}
	node, err := parser.parseExpression()
	if err != nil {
		return nil, err
	}
	if parser.pos != len(tokens) {
		return nil, fmt.Errorf("trailing tokens in matcher")
	}
	return node, nil
}

// stampFunctionNames replaces the closure value of FUNCTION tokens with the
// call's source name. Function calls and FUNCTION tokens are both emitted in
// source order, so the k-th call name belongs to the k-th FUNCTION token.
func stampFunctionNames(tokens []govaluate.ExpressionToken, rawMatcher string) []govaluate.ExpressionToken {
	names := scanFunctionNames(rawMatcher)
	ordinal := 0
	for i := range tokens {
		if tokens[i].Kind != govaluate.FUNCTION {
			continue
		}
		if ordinal < len(names) {
			tokens[i].Value = names[ordinal]
		} else {
			tokens[i].Value = "?"
		}
		ordinal++
	}
	return tokens
}

// scanFunctionNames returns the called function names in source order,
// ignoring the word "eval"/any identifier when it appears inside a string
// literal.
func scanFunctionNames(rawMatcher string) []string {
	var names []string
	i := 0
	for i < len(rawMatcher) {
		ch := rawMatcher[i]
		if ch == '\'' || ch == '"' {
			end := i + 1
			for end < len(rawMatcher) && rawMatcher[end] != ch {
				end++
			}
			i = end + 1
			continue
		}
		if isIdentifierStart(ch) {
			start := i
			i++
			for i < len(rawMatcher) && isIdentifierChar(rawMatcher[i]) {
				i++
			}
			name := rawMatcher[start:i]
			j := i
			for j < len(rawMatcher) && rawMatcher[j] == ' ' {
				j++
			}
			if j < len(rawMatcher) && rawMatcher[j] == '(' {
				names = append(names, name)
			}
			continue
		}
		i++
	}
	return names
}

func isIdentifierStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentifierChar(b byte) bool {
	return isIdentifierStart(b) || (b >= '0' && b <= '9')
}

// containsToken reports whether node references the variable token.
func containsToken(node *matcherNode, token string) bool {
	if node == nil {
		return false
	}
	if node.kind == nodeVariable && node.token == token {
		return true
	}
	for _, arg := range node.args {
		if containsToken(arg, token) {
			return true
		}
	}
	return false
}

// indexCompatibilityError explains why a matcher cannot be safely combined
// with a partition on policyToken.
type indexCompatibilityError struct {
	reason string
}

func (e *indexCompatibilityError) Error() string {
	return e.reason
}

// checkIndexCompatibility verifies that partitioning rules by policyToken can
// never change the matcher's result. The indexed policy token is safe only
// when every one of its occurrences is one side of an equality comparison
// whose other side is the matching request token, optionally OR-ed with an
// equality against the literal "*" (which maps to the wildcard bucket).
//
// Anything else is rejected conservatively: pattern functions (keyMatch,
// regexMatch, ...), regex/ordering/set comparators, eval(), ternaries and
// arbitrary function calls can all make a rule with a different partition key
// match the request, which would silently change the decision.
func checkIndexCompatibility(root *matcherNode, policyToken, requestToken string) error {
	if root == nil {
		return &indexCompatibilityError{reason: "matcher is empty"}
	}
	if !containsToken(root, policyToken) {
		return &indexCompatibilityError{reason: fmt.Sprintf(
			"matcher never uses policy token %q, so the partition key cannot prove rule separation", policyToken)}
	}
	return checkNode(root, policyToken, requestToken)
}

func checkNode(node *matcherNode, policyToken, requestToken string) error {
	switch node.kind {
	case nodeLiteral:
		return nil

	case nodeVariable:
		if node.token == policyToken {
			return &indexCompatibilityError{reason: fmt.Sprintf(
				"policy token %q is used outside an equality comparison; "+
					"rules in other partitions could still match the request", policyToken)}
		}
		return nil

	case nodeFunction:
		if node.fn == "eval" {
			for _, arg := range node.args {
				if containsToken(arg, policyToken) {
					return &indexCompatibilityError{reason: fmt.Sprintf(
						"policy token %q is used through eval(), which is not partition-safe", policyToken)}
				}
			}
		}
		for _, arg := range node.args {
			if containsToken(arg, policyToken) {
				return &indexCompatibilityError{reason: fmt.Sprintf(
					"policy token %q is passed to function %q; pattern/function matching is not partition-safe",
					policyToken, node.fn)}
			}
			if err := checkNode(arg, policyToken, requestToken); err != nil {
				return err
			}
		}
		return nil

	case nodeUnary:
		return checkNode(node.args[0], policyToken, requestToken)

	case nodeTernary:
		// A ternary may select values for the indexed token; treat it like an
		// arbitrary context and reject when the token is involved anywhere.
		for _, arg := range node.args {
			if containsToken(arg, policyToken) {
				return &indexCompatibilityError{reason: fmt.Sprintf(
					"policy token %q is used in a ternary expression, which is not partition-safe", policyToken)}
			}
			if err := checkNode(arg, policyToken, requestToken); err != nil {
				return err
			}
		}
		return nil

	case nodeBinary:
		switch node.token {
		case "&&", "||":
			for _, arg := range node.args {
				if err := checkNode(arg, policyToken, requestToken); err != nil {
					return err
				}
			}
			return nil
		case "==":
			if isSafeEquality(node, policyToken, requestToken) {
				return nil
			}
			if containsToken(node, policyToken) {
				return &indexCompatibilityError{reason: fmt.Sprintf(
					"policy token %q may only be compared for equality with request token %q "+
						"or the literal \"*\"", policyToken, requestToken)}
			}
			return nil
		default:
			if containsToken(node, policyToken) {
				return &indexCompatibilityError{reason: fmt.Sprintf(
					"operator %q on policy token %q is not partition-safe; only \"==\" is supported",
					node.token, policyToken)}
			}
			return nil
		}
	}
	return nil
}

// isSafeEquality accepts the exact shapes the partition invariant relies on:
//
//	policyToken == requestToken
//	requestToken == policyToken
//	policyToken == "*"
//	"*" == policyToken
//
// The literal form supports the wildcard bucket: such a rule is evaluated for
// every request regardless of its partition.
func isSafeEquality(node *matcherNode, policyToken, requestToken string) bool {
	if len(node.args) != 2 {
		return false
	}
	left, right := node.args[0], node.args[1]

	isVar := func(n *matcherNode, name string) bool {
		return n.kind == nodeVariable && n.token == name
	}
	isWildcard := func(n *matcherNode) bool {
		return n.kind == nodeLiteral && strings.Trim(n.token, `"'`) == "*"
	}

	switch {
	case isVar(left, policyToken) && isVar(right, requestToken):
		return true
	case isVar(right, policyToken) && isVar(left, requestToken):
		return true
	case isVar(left, policyToken) && isWildcard(right):
		return true
	case isVar(right, policyToken) && isWildcard(left):
		return true
	default:
		return false
	}
}

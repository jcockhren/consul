package xds

import (
	"fmt"

	envoylistener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	envoynetrbac "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/rbac/v2"
	envoyrbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	celcommon "github.com/google/cel-go/common"
	celparser "github.com/google/cel-go/parser"
	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/go-hclog"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Requires 1.12+ (ugh it's v2alpha in our version of the library!)
//
// L4: https://www.envoyproxy.io/docs/envoy/v1.12.0/configuration/listeners/network_filters/rbac_filter
//
// L7: https://www.envoyproxy.io/docs/envoy/v1.12.0/configuration/http/http_filters/rbac_filter
//
// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/rbac_filter
func makeRBACNetworkFilter(cfgSnap *proxycfg.ConfigSnapshot, logger hclog.Logger) (*envoylistener.Filter, error) {
	//TODO(rbac-ixns)

	// Note that we DON'T explicitly validate the trust-domain matches ours. See
	// the PR for this change for details.

	// TODO(banks): Implement revocation list checking here.

	type celSnippet struct {
		clause     string // CEL
		origClause string // CEL
		allow      bool
		precedence int // TODO(rbac-ixns): use this to optimize how the collapse works
	}

	const anyPath = `[^/]+`

	var (
		snippets        []*celSnippet
		stringConstants = make([]string, 0, len(cfgSnap.Intentions))
	)

	for _, ixn := range cfgSnap.Intentions {
		// we only care about the source end here; the dest was taken care of by the rest

		var principalPatt string
		switch {
		case ixn.SourceNS != structs.WildcardSpecifier && ixn.SourceName != structs.WildcardSpecifier:
			principalPatt = fmt.Sprintf(`^spiffe://%s/ns/%s/dc/%s/svc/%s$`,
				anyPath, ixn.SourceNS, anyPath, ixn.SourceName)
		case ixn.SourceNS != structs.WildcardSpecifier && ixn.SourceName == structs.WildcardSpecifier:
			principalPatt = fmt.Sprintf(`^spiffe://%s/ns/%s/dc/%s/svc/%s$`,
				anyPath, ixn.SourceNS, anyPath, anyPath)
		case ixn.SourceNS == structs.WildcardSpecifier && ixn.SourceName == structs.WildcardSpecifier:
			principalPatt = fmt.Sprintf(`^spiffe://%s/ns/%s/dc/%s/svc/%s$`,
				anyPath, anyPath, anyPath, anyPath)
		default:
			panic("TODO(rbac-ixns): not possible")
		}

		constantID := len(stringConstants)
		stringConstants = append(stringConstants, principalPatt)

		snippets = append(snippets, &celSnippet{
			clause:     fmt.Sprintf("matches(connection.uri_san_peer_certificate, stringvar(%d))", constantID),
			allow:      (ixn.Action == structs.IntentionActionAllow),
			precedence: ixn.Precedence,
		})
	}

	// Normalize: if we are in default-deny, all of our actual clauses must be allows
	var rules envoyrbac.RBAC
	if cfgSnap.DefaultACLPolicy == acl.Deny { // Note this feels a little bit backwards.
		// The RBAC policies grant access to principals. The rest is denied.
		// This is safe-list style access control. This is the default type.
		rules.Action = envoyrbac.RBAC_ALLOW

		// First we walk in descending precedence and squish denies into the
		// allows that follow. This makes sense because in the common case the
		// root will be default-deny, and our RBAC will be just listing all
		// conditions that are ALLOWED.
		if len(snippets) > 0 {
			mod := make([]*celSnippet, 0, len(snippets))
			for i, snip := range snippets {
				if snip.allow {
					mod = append(mod, snip)
				} else {
					for j := i + 1; j < len(snippets); j++ {
						snip2 := snippets[j]
						if snip2.origClause == "" {
							snip2.origClause = snip2.clause
						}

						snip2.clause = "(" + snip2.clause + ") AND !(" + snip.clause + ")"
					}
					// since this is default-deny, any trailing denies will just evaporate
				}
			}
			snippets = mod
		}

	} else {
		// The RBAC policies deny access to principals. The rest is allowed.
		// This is block-list style access control.
		rules.Action = envoyrbac.RBAC_DENY
		panic("TODO")
	}

	env, err := cel.NewEnv(cel.Macros(
		celparser.NewGlobalMacro("stringvar", 1, stringIDMacroExpander(stringConstants)),
	))
	if err != nil {
		return nil, err
	}

	rules.Policies = make(map[string]*envoyrbac.Policy)
	for i, snip := range snippets {
		ast, issues := env.Parse(snip.clause)
		if issues.Err() != nil {
			// TODO(rbac): better error context
			return nil, issues.Err()
		}

		// logger.Debug(
		// 	"envoy rbac",
		// 	"index", i,
		// 	"rules.action", rules.Action,
		// 	"cel", snip.clause,
		// 	"expr", ast.Expr(),
		// )

		// NOTE: all of this requires envoy 1.12+
		policy := &envoyrbac.Policy{
			Permissions: []*envoyrbac.Permission{
				{Rule: &envoyrbac.Permission_Any{Any: true}},
			},
			Principals: []*envoyrbac.Principal{
				{Identifier: &envoyrbac.Principal_Any{Any: true}},
				// {Identifier: &envoyrbac.Principal_Authenticated_{
				// 	Authenticated: &envoyrbac.Principal_Authenticated{
				// 		PrincipalName: &envoymatcher.StringMatcher{
				// 			MatchPattern: &envoymatcher.StringMatcher_Regex{
				// 				Regex: principalPatt,
				// 			},
				// 		},
				// 	},
				// }},
			},
			Condition: ast.Expr(),
		}

		policyID := fmt.Sprintf("consul-compiled-intentions-%d", i)

		rules.Policies[policyID] = policy
	}

	cfg := &envoynetrbac.RBAC{
		StatPrefix: "connect_authz",
		Rules:      &rules,
		// ShadowRules: &rules, // TODO
	}
	f, err := makeFilter("envoy.filters.network.rbac", cfg)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// stringIDMacroExpander returns a macro expander that accepts 1 numeric
// argument and looks that up by index in a table of strings and returns that
// instead.
func stringIDMacroExpander(stringsByID []string) celparser.MacroExpander {
	return func(eh celparser.ExprHelper, _ *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *celcommon.Error) {
		constExpr, ok := args[0].ExprKind.(*exprpb.Expr_ConstExpr)
		if !ok {
			location := eh.OffsetLocation(args[0].Id)
			return nil, &common.Error{
				Message:  "argument must be a constant",
				Location: location,
			}
		}
		int64Const, ok := constExpr.ConstExpr.ConstantKind.(*exprpb.Constant_Int64Value)
		if !ok {
			location := eh.OffsetLocation(args[0].Id)
			return nil, &common.Error{
				Message:  "argument must be an int64 constant",
				Location: location,
			}
		}
		constantID := int(int64Const.Int64Value)
		if constantID < 0 || constantID >= len(stringsByID) {
			location := eh.OffsetLocation(args[0].Id)
			return nil, &common.Error{
				Message:  fmt.Sprintf("stringvar %d does not exist", constantID),
				Location: location,
			}
		}
		v := stringsByID[constantID]

		return eh.LiteralString(v), nil
	}
}

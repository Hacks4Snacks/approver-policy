/*
Copyright 2021 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package manager

import (
	"context"
	"errors"
	"fmt"
	"path"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/approver/manager"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/manager/predicate"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

func TestPolicySetSchema(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(),
		testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		path.Join("..", "..", "..", "..", "deploy", "crds"),
	)
	for _, test := range []struct {
		name   string
		change func(*policyapi.CertificateRequestPolicySet)
		valid  bool
	}{
		{name: "valid set", valid: true},
		{name: "missing spec", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Spec = policyapi.CertificateRequestPolicySetSpec{}
		}},
		{name: "empty membership", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Spec.Policies = nil
		}},
		{name: "duplicate membership", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Spec.Policies = append(policySet.Spec.Policies, policySet.Spec.Policies[0])
		}},
		{name: "invalid policy name", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Spec.Policies[0].Name = "invalid/name"
		}},
		{name: "too many members", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			for index := range 64 {
				policySet.Spec.Policies = append(policySet.Spec.Policies, policyapi.CertificateRequestPolicyReference{Name: fmt.Sprintf("member-%d", index)})
			}
		}},
		{name: "missing selector", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Spec.Selector = nil
		}},
		{name: "empty selector", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Spec.Selector = &policyapi.CertificateRequestPolicySelector{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policySet := &policyapi.CertificateRequestPolicySet{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "schema-"},
				Spec: policyapi.CertificateRequestPolicySetSpec{
					Policies: []policyapi.CertificateRequestPolicyReference{{Name: "service"}},
					Selector: &policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				},
			}
			if test.change != nil {
				test.change(policySet)
			}
			err := env.AdminClient.Create(t.Context(), policySet)
			if !test.valid {
				require.True(t, apierrors.IsInvalid(err), "expected schema rejection, got %v", err)
				return
			}
			require.NoError(t, err)
			var stored policyapi.CertificateRequestPolicySet
			require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(policySet), &stored))
			assert.Equal(t, policySet.Spec, stored.Spec)
			policy := &policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "member-"},
				Spec: policyapi.CertificateRequestPolicySpec{
					Selector:     policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
					PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: policySet.Name},
				},
			}
			validSpec := policy.Spec
			require.NoError(t, env.AdminClient.Create(t.Context(), policy))
			var storedPolicy policyapi.CertificateRequestPolicy
			require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(policy), &storedPolicy))
			assert.Equal(t, policy.Spec.PolicySetRef, storedPolicy.Spec.PolicySetRef)
			invalidPolicy := &policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "invalid-member-"},
				Spec:       validSpec,
			}
			invalidPolicy.Spec.PolicySetRef = &policyapi.CertificateRequestPolicySetReference{Name: "invalid/name"}
			err = env.AdminClient.Create(t.Context(), invalidPolicy)
			require.True(t, apierrors.IsInvalid(err), "expected invalid set reference rejection, got %v", err)
		})
	}
}

func TestReviewPolicySets(t *testing.T) {
	for _, test := range []struct {
		name                string
		change              func(*policyapi.CertificateRequestPolicySet, *policyapi.CertificateRequestPolicy)
		missingMember       bool
		missingSet          bool
		denySetUse          bool
		denyPolicyUse       bool
		standalone          bool
		listError           bool
		rbacError           bool
		rbacEvaluationError bool
		memberRBACError     bool
		memberSelectorError bool
		disabled            bool
		otherSetFailure     string
		result              manager.ReviewResult
	}{
		{name: "complete set approves", result: manager.ResultApproved},
		{name: "other malformed set does not block complete set approval", otherSetFailure: "selector", result: manager.ResultApproved},
		{name: "other authorization error does not block complete set approval", otherSetFailure: "authorization", result: manager.ResultApproved},
		{name: "other member authorization error does not block complete set approval", otherSetFailure: "member authorization", result: manager.ResultApproved},
		{name: "other member selector error does not block complete set approval", otherSetFailure: "member selector", result: manager.ResultApproved},
		{name: "disabled sets cannot approve members", disabled: true, result: manager.ResultUnprocessed},
		{name: "disabled sets still allow standalone approval", disabled: true, standalone: true, result: manager.ResultApproved},
		{name: "disabled sets do not access a missing API", disabled: true, missingSet: true, result: manager.ResultUnprocessed},
		{name: "missing member defers denial", missingMember: true, result: manager.ResultUnprocessed},
		{name: "missing set prevents standalone fallback", missingSet: true, result: manager.ResultUnprocessed},
		{name: "set use is required", denySetUse: true, result: manager.ResultDenied},
		{name: "member use remains required", denyPolicyUse: true, result: manager.ResultDenied},
		{name: "unauthorized incomplete set does not defer denial", missingMember: true, denySetUse: true, result: manager.ResultDenied},
		{name: "unauthorized missing set does not defer denial", missingSet: true, denySetUse: true, result: manager.ResultDenied},
		{name: "set list errors cannot approve", listError: true},
		{name: "authorization errors cannot approve", rbacError: true},
		{name: "set list errors do not block standalone approval", listError: true, standalone: true, result: manager.ResultApproved},
		{name: "set authorization errors do not block standalone approval", rbacError: true, standalone: true, result: manager.ResultApproved},
		{name: "inconclusive set authorization prevents terminal denial", missingMember: true, rbacEvaluationError: true},
		{name: "inconclusive set authorization preserves standalone approval", rbacEvaluationError: true, standalone: true, result: manager.ResultApproved},
		{name: "member authorization errors prevent terminal denial", memberRBACError: true},
		{name: "member authorization errors preserve standalone approval", memberRBACError: true, standalone: true, result: manager.ResultApproved},
		{name: "disabled member authorization errors preserve standalone approval", disabled: true, memberRBACError: true, standalone: true, result: manager.ResultApproved},
		{name: "unauthorized set member errors preserve standalone approval", denySetUse: true, memberRBACError: true, standalone: true, result: manager.ResultApproved},
		{name: "missing set member errors preserve standalone approval", missingSet: true, memberRBACError: true, standalone: true, result: manager.ResultApproved},
		{name: "member selector errors prevent terminal denial", memberSelectorError: true},
		{name: "member selector errors preserve standalone approval", memberSelectorError: true, standalone: true, result: manager.ResultApproved},
		{name: "disabled member selector errors preserve standalone approval", disabled: true, memberSelectorError: true, standalone: true, result: manager.ResultApproved},
		{name: "malformed unauthorized set does not block denial", denySetUse: true, change: func(policySet *policyapi.CertificateRequestPolicySet, _ *policyapi.CertificateRequestPolicy) {
			policySet.Spec.Selector.Namespace = &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: map[string]string{"invalid key": "value"}}
		}, result: manager.ResultDenied},
		{name: "malformed set does not block standalone approval", standalone: true, change: func(policySet *policyapi.CertificateRequestPolicySet, _ *policyapi.CertificateRequestPolicy) {
			policySet.Spec.Selector.Namespace = &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: map[string]string{"invalid key": "value"}}
		}, result: manager.ResultApproved},
		{name: "independent approval remains available", missingMember: true, standalone: true, result: manager.ResultApproved},
		{name: "stale member blocks evaluation", change: func(_ *policyapi.CertificateRequestPolicySet, policy *policyapi.CertificateRequestPolicy) {
			policy.Generation++
		}, result: manager.ResultUnprocessed},
		{name: "not ready member blocks evaluation", change: func(_ *policyapi.CertificateRequestPolicySet, policy *policyapi.CertificateRequestPolicy) {
			policy.Status.Conditions[0].Status = metav1.ConditionFalse
		}, result: manager.ResultUnprocessed},
		{name: "foreign member blocks evaluation", change: func(_ *policyapi.CertificateRequestPolicySet, policy *policyapi.CertificateRequestPolicy) {
			policy.Spec.PolicySetRef.Name = "other"
		}, result: manager.ResultUnprocessed},
		{name: "empty set reference cannot approve", change: func(_ *policyapi.CertificateRequestPolicySet, policy *policyapi.CertificateRequestPolicy) {
			policy.Spec.PolicySetRef.Name = ""
		}, result: manager.ResultUnprocessed},
		{name: "unlisted member cannot approve", change: func(policySet *policyapi.CertificateRequestPolicySet, _ *policyapi.CertificateRequestPolicy) {
			policySet.Spec.Policies = policySet.Spec.Policies[1:]
		}, result: manager.ResultDenied},
		{name: "set selector remains required", change: func(policySet *policyapi.CertificateRequestPolicySet, _ *policyapi.CertificateRequestPolicy) {
			issuer := "other"
			policySet.Spec.Selector.IssuerRef = &policyapi.CertificateRequestPolicySelectorIssuerRef{Name: &issuer}
		}, result: manager.ResultDenied},
		{name: "member selector remains required", change: func(_ *policyapi.CertificateRequestPolicySet, policy *policyapi.CertificateRequestPolicy) {
			issuer := "other"
			policy.Spec.Selector.IssuerRef = &policyapi.CertificateRequestPolicySelectorIssuerRef{Name: &issuer}
		}, result: manager.ResultDenied},
		{name: "unrelated incomplete set does not defer denial", missingMember: true, change: func(policySet *policyapi.CertificateRequestPolicySet, _ *policyapi.CertificateRequestPolicy) {
			policySet.Spec.Selector.Namespace = &policyapi.CertificateRequestPolicySelectorNamespace{MatchNames: []string{"other-namespace"}}
		}, result: manager.ResultDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			policySet := &policyapi.CertificateRequestPolicySet{
				ObjectMeta: metav1.ObjectMeta{Name: "services"},
				Spec: policyapi.CertificateRequestPolicySetSpec{
					Policies: []policyapi.CertificateRequestPolicyReference{{Name: "allow"}, {Name: "deny"}},
					Selector: &policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				},
			}
			newPolicy := func(name string) *policyapi.CertificateRequestPolicy {
				return &policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 2},
					Spec:       policyapi.CertificateRequestPolicySpec{PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: "services"}},
					Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{{
						Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: 2,
					}}},
				}
			}
			allow, deny, independent := newPolicy("allow"), newPolicy("deny"), newPolicy("independent")
			independent.Spec.PolicySetRef = nil
			if test.change != nil {
				test.change(policySet, allow)
			}
			if test.memberSelectorError {
				allow.Spec.Selector.Namespace = &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: map[string]string{"invalid key": "value"}}
			}
			objects := []client.Object{deny, independent, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}}
			if !test.missingMember {
				objects = append(objects, allow)
			}
			if !test.missingSet {
				objects = append(objects, policySet)
			}
			if test.otherSetFailure != "" {
				otherSet := policySet.DeepCopy()
				otherSet.Name = "other-set"
				if test.otherSetFailure == "selector" {
					otherSet.Spec.Selector.Namespace = &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: map[string]string{"invalid key": "value"}}
				}
				if test.otherSetFailure == "member authorization" || test.otherSetFailure == "member selector" {
					otherMember := newPolicy("other-member")
					otherMember.Spec.PolicySetRef.Name = otherSet.Name
					otherSet.Spec.Policies = []policyapi.CertificateRequestPolicyReference{{Name: otherMember.Name}}
					if test.otherSetFailure == "member selector" {
						otherMember.Spec.Selector.Namespace = &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: map[string]string{"invalid key": "value"}}
					}
					objects = append(objects, otherMember)
				}
				objects = append(objects, otherSet)
			}
			apiClient := fakeclient.NewClientBuilder().WithScheme(policyapi.GlobalScheme).WithObjects(objects...).
				WithInterceptorFuncs(interceptor.Funcs{List: func(ctx context.Context, apiClient client.WithWatch, list client.ObjectList, options ...client.ListOption) error {
					if _, isSet := list.(*policyapi.CertificateRequestPolicySetList); isSet && test.disabled {
						t.Fatal("disabled feature must not access the policy-set API")
					}
					if _, isSet := list.(*policyapi.CertificateRequestPolicySetList); isSet && test.listError {
						return errors.New("synthetic set list error")
					}
					return apiClient.List(ctx, list, options...)
				}, Create: func(_ context.Context, _ client.WithWatch, object client.Object, _ ...client.CreateOption) error {
					review, ok := object.(*authzv1.SubjectAccessReview)
					require.True(t, ok)
					attributes := review.Spec.ResourceAttributes
					if test.disabled && attributes.Resource == "certificaterequestpolicysets" {
						t.Fatal("disabled feature must not authorize policy sets")
					}
					if test.rbacError && attributes.Resource == "certificaterequestpolicysets" {
						return errors.New("synthetic set authorization error")
					}
					if test.rbacEvaluationError && attributes.Resource == "certificaterequestpolicysets" {
						review.Status.EvaluationError = "authorization webhook timed out"
						return nil
					}
					if attributes.Resource == "certificaterequestpolicies" && ((test.memberRBACError && attributes.Name == "allow") ||
						(test.otherSetFailure == "member authorization" && attributes.Name == "other-member")) {
						return errors.New("synthetic member authorization error")
					}
					if test.otherSetFailure == "authorization" && attributes.Resource == "certificaterequestpolicysets" && attributes.Name == "other-set" {
						return errors.New("synthetic other-set authorization error")
					}
					review.Status.Allowed = !(test.denySetUse && attributes.Resource == "certificaterequestpolicysets") &&
						!(test.denyPolicyUse && attributes.Resource == "certificaterequestpolicies" && attributes.Name == "allow")
					return nil
				}}).Build()
			evaluator := fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
				if policy.Name == "allow" || (test.standalone && policy.Name == "independent") {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
				}
				return approver.EvaluationResponse{Result: approver.ResultDenied}, nil
			})
			response, err := New(apiClient, []approver.Evaluator{evaluator}, !test.disabled).Review(t.Context(), &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "request", Namespace: "tenant"},
				Spec:       cmapi.CertificateRequestSpec{Username: "requester", IssuerRef: cmmeta.IssuerReference{Name: "issuer"}},
			})
			if (test.listError || test.rbacError || test.rbacEvaluationError || test.memberRBACError || test.memberSelectorError) && !test.standalone {
				require.Error(t, err)
				assert.NotEqual(t, manager.ResultApproved, response.Result)
				assert.NotEqual(t, manager.ResultDenied, response.Result)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.result, response.Result, response.Message)
			if test.result == manager.ResultUnprocessed {
				if test.disabled {
					assert.Contains(t, response.Message, "disabled")
					assert.Zero(t, response.RequeueAfter)
				} else {
					assert.Contains(t, response.Message, "policy sets")
					assert.Equal(t, time.Minute, response.RequeueAfter)
				}
			}
		})
	}
}

func TestReviewPolicyReadiness(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("policySets=%t", enabled), func(t *testing.T) {
			for _, test := range []struct {
				name               string
				status             metav1.ConditionStatus
				observedGeneration int64
				independent        bool
				result             manager.ReviewResult
			}{
				{name: "current ready approves", status: metav1.ConditionTrue, observedGeneration: 2, result: manager.ResultApproved},
				{name: "current not ready permits fallback denial", status: metav1.ConditionFalse, observedGeneration: 2, result: manager.ResultDenied},
				{name: "missing readiness defers denial", result: manager.ResultUnprocessed},
				{name: "unknown readiness defers denial", status: metav1.ConditionUnknown, observedGeneration: 2, result: manager.ResultUnprocessed},
				{name: "stale ready defers denial", status: metav1.ConditionTrue, observedGeneration: 1, result: manager.ResultUnprocessed},
				{name: "stale not ready defers denial", status: metav1.ConditionFalse, observedGeneration: 1, result: manager.ResultUnprocessed},
				{name: "future readiness defers denial", status: metav1.ConditionTrue, observedGeneration: 3, result: manager.ResultUnprocessed},
				{name: "stale ready preserves independent approval", status: metav1.ConditionTrue, observedGeneration: 1, independent: true, result: manager.ResultApproved},
				{name: "stale not ready preserves independent approval", status: metav1.ConditionFalse, observedGeneration: 1, independent: true, result: manager.ResultApproved},
				{name: "unknown readiness preserves independent approval", status: metav1.ConditionUnknown, observedGeneration: 2, independent: true, result: manager.ResultApproved},
			} {
				t.Run(test.name, func(t *testing.T) {
					allow := &policyapi.CertificateRequestPolicy{
						ObjectMeta: metav1.ObjectMeta{Name: "allow", Generation: 2},
						Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
							IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
						}},
					}
					if test.status != "" {
						allow.Status.Conditions = []metav1.Condition{{
							Type: policyapi.ConditionTypeReady, Status: test.status, ObservedGeneration: test.observedGeneration,
						}}
					}
					independent := allow.DeepCopy()
					independent.Name = "independent"
					independent.Status.Conditions = []metav1.Condition{{
						Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: 2,
					}}
					apiClient := fakeclient.NewClientBuilder().WithScheme(policyapi.GlobalScheme).WithObjects(allow, independent).
						WithInterceptorFuncs(interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, object client.Object, _ ...client.CreateOption) error {
							object.(*authzv1.SubjectAccessReview).Status.Allowed = true
							return nil
						}}).Build()
					evaluator := fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
						if policy.Name == "allow" || test.independent {
							return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
						}
						return approver.EvaluationResponse{Result: approver.ResultDenied}, nil
					})
					response, err := New(apiClient, []approver.Evaluator{evaluator}, enabled).Review(t.Context(), &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{Name: "request", Namespace: "tenant"},
						Spec:       cmapi.CertificateRequestSpec{Username: "requester", IssuerRef: cmmeta.IssuerReference{Name: "issuer"}},
					})
					require.NoError(t, err)
					assert.Equal(t, test.result, response.Result, response.Message)
				})
			}
		})
	}
}

func BenchmarkReviewPolicySets(b *testing.B) {
	for _, count := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("sets=%d", count), func(b *testing.B) {
			var objects []client.Object
			for index := range count {
				name := fmt.Sprintf("set-%d", index)
				objects = append(objects,
					&policyapi.CertificateRequestPolicySet{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: policyapi.CertificateRequestPolicySetSpec{
						Policies: []policyapi.CertificateRequestPolicyReference{{Name: name}},
						Selector: &policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
					}},
					&policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1}, Spec: policyapi.CertificateRequestPolicySpec{
						PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: name},
					}, Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{{Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: 1}}}},
				)
			}
			authorizations := 0
			apiClient := fakeclient.NewClientBuilder().WithScheme(policyapi.GlobalScheme).WithObjects(objects...).
				WithInterceptorFuncs(interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, object client.Object, _ ...client.CreateOption) error {
					authorizations++
					object.(*authzv1.SubjectAccessReview).Status.Allowed = true
					return nil
				}}).Build()
			evaluator := fake.NewFakeEvaluator().WithEvaluate(func(context.Context, *policyapi.CertificateRequestPolicy, *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
				return approver.EvaluationResponse{Result: approver.ResultDenied}, nil
			})
			reviewer := New(apiClient, []approver.Evaluator{evaluator}, true)
			request := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant"}, Spec: cmapi.CertificateRequestSpec{Username: "requester"}}
			b.ReportAllocs()
			for b.Loop() {
				response, err := reviewer.Review(b.Context(), request)
				if err != nil || response.Result != manager.ResultDenied {
					b.Fatalf("expected denial, got %+v, %v", response, err)
				}
			}
			b.ReportMetric(float64(authorizations)/float64(b.N), "authz/op")
		})
	}
}

func Test_Review(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(),
		testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		path.Join("..", "..", "..", "..", "deploy", "crds"),
	)

	expNoEvaluation := func(t *testing.T) approver.Evaluator {
		return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
			t.Fatal("unexpected evaluator call")
			return approver.EvaluationResponse{}, nil
		})
	}

	tests := map[string]struct {
		evaluator        func(t *testing.T) approver.Evaluator
		predicate        func(t *testing.T) predicate.Predicate
		policies         []policyapi.CertificateRequestPolicy
		setReadyPolicies []string // policy names to set Ready condition on after creation
		expResponse      manager.ReviewResponse
		expErr           bool
	}{
		"if no CertificateRequestPolicies exist, return ResultUnprocessed": {
			evaluator: expNoEvaluation,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, _ []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					t.Fatal("unexpected predicate call")
					return nil, nil
				}
			},
			policies:    nil,
			expResponse: manager.ReviewResponse{Result: manager.ResultUnprocessed, Message: "No CertificateRequestPolicies exist"},
			expErr:      false,
		},
		"if predicate returns an error, return an error": {
			evaluator: expNoEvaluation,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, _ []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return nil, errors.New("this is an error")
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			expResponse: manager.ReviewResponse{},
			expErr:      true,
		},
		"if predicate returns no policies, return ResultUnprocessed": {
			evaluator: expNoEvaluation,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, _ []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return nil, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			expResponse: manager.ReviewResponse{Result: manager.ResultUnprocessed, Message: "No CertificateRequestPolicies bound or applicable"},
			expErr:      false,
		},
		"if single policy returns but evaluator denies, return ResultDenied": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			setReadyPolicies: []string{"test-policy-a"},
			expResponse:      manager.ReviewResponse{Result: manager.ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response]"},
			expErr:           false,
		},
		"if single policy returns and evaluator returns not-denied, return ResultApproved": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is a not-denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			setReadyPolicies: []string{"test-policy-a"},
			expResponse:      manager.ReviewResponse{Result: manager.ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-a"`},
			expErr:           false,
		},
		"if two policies returned and evaluator returns one not-denied, return ResultApproved": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					if policy.Name == "test-policy-b" {
						return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is an approved response"}, nil
					}
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			setReadyPolicies: []string{"test-policy-a", "test-policy-b"},
			expResponse:      manager.ReviewResponse{Result: manager.ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-b"`},
			expErr:           false,
		},
		"if two policies returned and both return denied, return ResultDenied": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			setReadyPolicies: []string{"test-policy-a", "test-policy-b"},
			expResponse:      manager.ReviewResponse{Result: manager.ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response] [test-policy-b: this is a denied response]"},
			expErr:           false,
		},
		"if evaluator denies but some policies are unreconciled, return ResultUnprocessed": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-deny"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-unreconciled"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			setReadyPolicies: []string{"test-policy-deny"},
			expResponse: manager.ReviewResponse{
				Result:  manager.ResultUnprocessed,
				Message: "Not all policies are ready for evaluation; refusing to deny pending policy readiness: [test-policy-deny: this is a denied response]",
			},
			expErr: false,
		},
	}

	ctx := t.Context()
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				for _, obj := range test.policies {
					if err := env.AdminClient.Delete(ctx, &obj); /* #nosec G601 -- Func drops pointer at end of call. */ err != nil {
						// Don't Fatal here as a ditch effort to at least try to clean-up
						// everything.
						t.Errorf("failed to delete policy: %s", err)
					}
				}
			})

			for _, obj := range test.policies {
				if err := env.AdminClient.Create(ctx, &obj); /* #nosec G601 -- Func drops pointer at end of call. */ err != nil {
					t.Fatalf("failed to create new policy: %s", err)
				}
			}

			// Set the Ready condition on specified policies via status subresource.
			for _, name := range test.setReadyPolicies {
				var policy policyapi.CertificateRequestPolicy
				if err := env.AdminClient.Get(ctx, client.ObjectKey{Name: name}, &policy); err != nil {
					t.Fatalf("failed to get policy %q for status update: %s", name, err)
				}
				policy.Status.Conditions = []metav1.Condition{
					{
						Type:               policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						ObservedGeneration: policy.Generation,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						LastTransitionTime: metav1.Now(),
					},
				}
				if err := env.AdminClient.Status().Update(ctx, &policy); err != nil {
					t.Fatalf("failed to update status for policy %q: %s", name, err)
				}
			}

			mngr := &mngr{
				reader:         env.AdminClient,
				readyPredicate: predicate.Ready,
				predicates:     []predicate.Predicate{test.predicate(t)},
				evaluators:     []approver.Evaluator{test.evaluator(t)},
			}

			response, err := mngr.Review(ctx, &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-req"},
				Spec: cmapi.CertificateRequestSpec{
					Username: "example",
					IssuerRef: cmmeta.IssuerReference{
						Name:  "test-name",
						Kind:  "test-kind",
						Group: "test-group",
					},
				},
			})

			assert.Equalf(t, test.expErr, err != nil, "%v", err)
			assert.Equal(t, test.expResponse, response)
		})
	}
}

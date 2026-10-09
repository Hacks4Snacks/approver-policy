package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

func TestPolicySetReadiness(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*policyapi.CertificateRequestPolicySet, map[string]policyapi.CertificateRequestPolicy)
		status metav1.ConditionStatus
		reason string
	}{
		{name: "complete", status: metav1.ConditionTrue, reason: "Ready"},
		{name: "missing member", change: func(_ *policyapi.CertificateRequestPolicySet, policies map[string]policyapi.CertificateRequestPolicy) {
			delete(policies, "allow")
		}, status: metav1.ConditionFalse, reason: "PolicyMissing"},
		{name: "stale readiness", change: func(_ *policyapi.CertificateRequestPolicySet, policies map[string]policyapi.CertificateRequestPolicy) {
			policy := policies["allow"]
			policy.Generation++
			policies["allow"] = policy
		}, status: metav1.ConditionFalse, reason: "PolicyNotReady"},
		{name: "not ready", change: func(_ *policyapi.CertificateRequestPolicySet, policies map[string]policyapi.CertificateRequestPolicy) {
			policies["allow"].Status.Conditions[0].Status = metav1.ConditionFalse
		}, status: metav1.ConditionFalse, reason: "PolicyNotReady"},
		{name: "foreign membership", change: func(_ *policyapi.CertificateRequestPolicySet, policies map[string]policyapi.CertificateRequestPolicy) {
			policies["allow"].Spec.PolicySetRef.Name = "other"
		}, status: metav1.ConditionFalse, reason: "MembershipMismatch"},
		{name: "deleting member", change: func(_ *policyapi.CertificateRequestPolicySet, policies map[string]policyapi.CertificateRequestPolicy) {
			policy := policies["allow"]
			now := metav1.Now()
			policy.DeletionTimestamp = &now
			policies["allow"] = policy
		}, status: metav1.ConditionFalse, reason: "PolicyDeleting"},
		{name: "duplicate member", change: func(policySet *policyapi.CertificateRequestPolicySet, _ map[string]policyapi.CertificateRequestPolicy) {
			policySet.Spec.Policies = append(policySet.Spec.Policies, policySet.Spec.Policies[0])
		}, status: metav1.ConditionFalse, reason: "InvalidMembership"},
		{name: "empty set", change: func(policySet *policyapi.CertificateRequestPolicySet, _ map[string]policyapi.CertificateRequestPolicy) {
			policySet.Spec.Policies = nil
		}, status: metav1.ConditionFalse, reason: "InvalidMembership"},
		{name: "empty selector", change: func(policySet *policyapi.CertificateRequestPolicySet, _ map[string]policyapi.CertificateRequestPolicy) {
			policySet.Spec.Selector = &policyapi.CertificateRequestPolicySelector{}
		}, status: metav1.ConditionFalse, reason: "InvalidSelector"},
		{name: "invalid namespace label", change: func(policySet *policyapi.CertificateRequestPolicySet, _ map[string]policyapi.CertificateRequestPolicy) {
			policySet.Spec.Selector.Namespace = &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: map[string]string{"invalid key": "value"}}
		}, status: metav1.ConditionFalse, reason: "InvalidSelector"},
		{name: "deleting set", change: func(policySet *policyapi.CertificateRequestPolicySet, _ map[string]policyapi.CertificateRequestPolicy) {
			now := metav1.Now()
			policySet.DeletionTimestamp = &now
		}, status: metav1.ConditionFalse, reason: "Deleting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policySet := &policyapi.CertificateRequestPolicySet{
				ObjectMeta: metav1.ObjectMeta{Name: "services"},
				Spec: policyapi.CertificateRequestPolicySetSpec{
					Selector: &policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
					Policies: []policyapi.CertificateRequestPolicyReference{{Name: "allow"}, {Name: "deny"}},
				},
			}
			policies := make(map[string]policyapi.CertificateRequestPolicy)
			for _, name := range []string{"allow", "deny"} {
				policies[name] = policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 2},
					Spec: policyapi.CertificateRequestPolicySpec{
						PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: "services"},
					},
					Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{{
						Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: 2,
					}}},
				}
			}
			if test.change != nil {
				test.change(policySet, policies)
			}
			status, reason, message := PolicySetReadiness(policySet, policies)
			assert.Equal(t, test.status, status)
			assert.Equal(t, test.reason, reason)
			assert.NotEmpty(t, message)
		})
	}
}

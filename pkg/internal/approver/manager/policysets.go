package manager

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver/manager"
	"github.com/cert-manager/approver-policy/pkg/internal/util"
)

func (m *mngr) policySetMembers(ctx context.Context, request *cmapi.CertificateRequest, applicable, all []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, []string, error) {
	var eligible []policyapi.CertificateRequestPolicy
	referencedSets := make(map[string]struct{})
	for _, policy := range applicable {
		if policy.Spec.PolicySetRef == nil {
			eligible = append(eligible, policy)
		} else {
			referencedSets[policy.Spec.PolicySetRef.Name] = struct{}{}
		}
	}
	if !m.enablePolicySets {
		names := make([]string, 0, len(referencedSets))
		for name := range referencedSets {
			names = append(names, name)
		}
		sort.Strings(names)
		return eligible, names, nil
	}
	var policySets policyapi.CertificateRequestPolicySetList
	if err := m.reader.List(ctx, &policySets); err != nil {
		return eligible, nil, fmt.Errorf("failed to list policy sets: %w", err)
	}
	byName := make(map[string]policyapi.CertificateRequestPolicy, len(all))
	for _, policy := range all {
		byName[policy.Name] = policy
	}
	setsByName := make(map[string]policyapi.CertificateRequestPolicySet, len(policySets.Items))
	var candidates []policyapi.CertificateRequestPolicy
	for _, policySet := range policySets.Items {
		setsByName[policySet.Name] = policySet
		selector := policyapi.CertificateRequestPolicySelector{}
		if policySet.Spec.Selector != nil {
			selector = *policySet.Spec.Selector
		}
		candidates = append(candidates, policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policySet.Name},
			Spec:       policyapi.CertificateRequestPolicySpec{Selector: selector},
		})
	}
	missingSets := make(map[string]struct{})
	for _, policy := range applicable {
		if policy.Spec.PolicySetRef == nil {
			continue
		}
		setName := policy.Spec.PolicySetRef.Name
		if _, exists := setsByName[setName]; exists {
			continue
		}
		if _, exists := missingSets[setName]; exists {
			continue
		}
		missingSets[setName] = struct{}{}
		candidates = append(candidates, policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: setName},
			Spec:       policyapi.CertificateRequestPolicySpec{Selector: policy.Spec.Selector},
		})
	}
	readyMembers := make(map[string]string)
	pending := make(map[string]struct{})
	var evaluationErrors []error
	for _, candidate := range candidates {
		matching := []policyapi.CertificateRequestPolicy{candidate}
		for _, pred := range m.setPredicates {
			var err error
			matching, err = pred(ctx, request, matching)
			if err != nil {
				evaluationErrors = append(evaluationErrors, fmt.Errorf("failed to match policy set %q: %w", candidate.Name, err))
				matching = nil
			}
			if len(matching) == 0 {
				break
			}
		}
		if len(matching) == 0 {
			continue
		}
		policySet, exists := setsByName[candidate.Name]
		if !exists {
			pending[candidate.Name] = struct{}{}
			continue
		}
		status, _, _ := util.PolicySetReadiness(&policySet, byName)
		if status != metav1.ConditionTrue {
			pending[policySet.Name] = struct{}{}
			continue
		}
		for _, reference := range policySet.Spec.Policies {
			readyMembers[reference.Name] = policySet.Name
		}
	}
	for _, policy := range applicable {
		if policy.Spec.PolicySetRef == nil {
			continue
		}
		setName := policy.Spec.PolicySetRef.Name
		if readySet, exists := readyMembers[policy.Name]; exists && readySet == setName {
			eligible = append(eligible, policy)
		}
	}
	pendingNames := make([]string, 0, len(pending))
	for name := range pending {
		pendingNames = append(pendingNames, name)
	}
	sort.Strings(pendingNames)
	return eligible, pendingNames, errors.Join(evaluationErrors...)
}

func (m *mngr) pendingPolicySets(names []string) manager.ReviewResponse {
	if !m.enablePolicySets {
		return manager.ReviewResponse{
			Result:  manager.ResultUnprocessed,
			Message: "Policy set evaluation is disabled; referenced policies remain inactive",
		}
	}
	return manager.ReviewResponse{
		Result:       manager.ResultUnprocessed,
		Message:      "Waiting for complete, current-generation policy sets: " + strings.Join(names, ", "),
		RequeueAfter: time.Minute,
	}
}

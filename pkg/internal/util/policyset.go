package util

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

// PolicySetReadiness checks membership and current-generation readiness.
func PolicySetReadiness(policySet *policyapi.CertificateRequestPolicySet, policies map[string]policyapi.CertificateRequestPolicy) (metav1.ConditionStatus, string, string) {
	if policySet.Spec.Selector == nil || len(policySet.Spec.Policies) == 0 {
		return metav1.ConditionFalse, "InvalidMembership", "The set must declare a selector and at least one policy"
	}
	if !policySet.DeletionTimestamp.IsZero() {
		return metav1.ConditionFalse, "Deleting", "The set is being deleted"
	}
	if errors := ValidatePolicySelector(policySet.Spec.Selector, field.NewPath("spec", "selector")); len(errors) > 0 {
		return metav1.ConditionFalse, "InvalidSelector", errors.ToAggregate().Error()
	}
	seen := make(map[string]struct{}, len(policySet.Spec.Policies))
	for _, reference := range policySet.Spec.Policies {
		if _, exists := seen[reference.Name]; exists || reference.Name == "" {
			return metav1.ConditionFalse, "InvalidMembership", "Policy names must be nonempty and unique"
		}
		seen[reference.Name] = struct{}{}
		policy, exists := policies[reference.Name]
		if !exists {
			return metav1.ConditionFalse, "PolicyMissing", fmt.Sprintf("Policy %q does not exist", reference.Name)
		}
		if policy.Spec.PolicySetRef == nil || policy.Spec.PolicySetRef.Name != policySet.Name {
			return metav1.ConditionFalse, "MembershipMismatch", fmt.Sprintf("Policy %q does not reference this set", reference.Name)
		}
		if !policy.DeletionTimestamp.IsZero() {
			return metav1.ConditionFalse, "PolicyDeleting", fmt.Sprintf("Policy %q is being deleted", reference.Name)
		}
		ready := false
		for _, condition := range policy.Status.Conditions {
			if condition.Type == policyapi.ConditionTypeReady && condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == policy.Generation {
				ready = true
				break
			}
		}
		if !ready {
			return metav1.ConditionFalse, "PolicyNotReady", fmt.Sprintf("Policy %q is not Ready for its current generation", reference.Name)
		}
	}
	return metav1.ConditionTrue, "Ready", "All expected policies are Ready for their current generations"
}

// ValidatePolicySelector checks the shared issuer and namespace selector contract.
func ValidatePolicySelector(selector *policyapi.CertificateRequestPolicySelector, path *field.Path) field.ErrorList {
	var errors field.ErrorList
	if selector == nil || (selector.IssuerRef == nil && selector.Namespace == nil) {
		return append(errors, field.Required(path, "one of issuerRef or namespace must be defined, hint: `{}` on either matches everything"))
	}
	if namespace := selector.Namespace; namespace != nil && len(namespace.MatchLabels) > 0 {
		if _, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: namespace.MatchLabels}); err != nil {
			errors = append(errors, field.Invalid(path.Child("namespace", "matchLabels"), namespace.MatchLabels, err.Error()))
		}
	}
	return errors
}

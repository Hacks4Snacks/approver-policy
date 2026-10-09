package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=cert-manager,shortName=crps,scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=`.status.conditions[?(@.type == "Ready")].status`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// CertificateRequestPolicySet declares a complete group of approval policies.
type CertificateRequestPolicySet struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is the standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec declares the request scope and expected policies.
	// +required
	Spec CertificateRequestPolicySetSpec `json:"spec,omitzero"`

	// status reports the readiness of the expected policies.
	// +optional
	Status *CertificateRequestPolicySetStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CertificateRequestPolicySetList contains policy sets.
type CertificateRequestPolicySetList struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is the standard list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	// items contains the policy sets.
	Items []CertificateRequestPolicySet `json:"items"`
}

// CertificateRequestPolicySetSpec declares policy set membership and scope.
type CertificateRequestPolicySetSpec struct {
	// policies names every expected member. Each member must reference this set
	// through its policySetRef. Membership does not grant permission to use it.
	// +required
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Policies []CertificateRequestPolicyReference `json:"policies,omitempty"`

	// selector scopes the set independently of whether its members exist.
	// +required
	Selector *CertificateRequestPolicySetSelector `json:"selector,omitempty"`
}

// CertificateRequestPolicySetSelector scopes requests subject to set completeness.
// +kubebuilder:validation:XValidation:rule="has(self.issuerRef) || has(self.issuerRefs) || has(self.namespace)",message="at least issuerRef, issuerRefs, or namespace must be specified"
// +kubebuilder:validation:XValidation:rule="!(has(self.issuerRef) && has(self.issuerRefs))",message="issuerRef and issuerRefs are mutually exclusive"
type CertificateRequestPolicySetSelector struct {
	// issuerRef matches a single issuer pattern. An empty object matches all
	// issuers. This field is mutually exclusive with issuerRefs.
	// +optional
	IssuerRef *CertificateRequestPolicySelectorIssuerRef `json:"issuerRef,omitempty"`

	// issuerRefs matches any of the listed issuer patterns. Fields within each
	// pattern must all match. This field is mutually exclusive with issuerRef.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	IssuerRefs []CertificateRequestPolicySelectorIssuerRef `json:"issuerRefs,omitempty"` //nolint:kubeapilinter // arrayofstruct: issuer patterns deliberately allow omitted fields and {} wildcard matching.

	// namespace must also match when specified. Omitting it selects every
	// namespace, subject to the issuer selector and requester permissions.
	// +optional
	Namespace *CertificateRequestPolicySelectorNamespace `json:"namespace,omitempty"`
}

// CertificateRequestPolicyReference identifies an expected policy by name.
type CertificateRequestPolicyReference struct {
	// name is the cluster-scoped CertificateRequestPolicy name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
}

// CertificateRequestPolicySetReference opts a policy into exactly one set.
type CertificateRequestPolicySetReference struct {
	// name is the cluster-scoped CertificateRequestPolicySet name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
}

// CertificateRequestPolicySetStatus reports collective policy readiness.
type CertificateRequestPolicySetStatus struct {
	// conditions describes whether all members are Ready for their current
	// generations. Evaluation also checks members directly to detect later drift.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` //nolint:tagalign // kube-api-linter requires this conditions tag order.
}

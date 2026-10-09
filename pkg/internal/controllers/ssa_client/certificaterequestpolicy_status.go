/*
Copyright 2023 The cert-manager Authors.

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

package ssa_client

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

type certificateRequestPolicyStatusStatusApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Status                           *policyapi.CertificateRequestPolicyStatus `json:"status,omitempty"`
}

type certificateRequestPolicySetStatusApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Status                           *policyapi.CertificateRequestPolicySetStatus `json:"status,omitempty"`
}

// GenerateCertificateRequestPolicySetStatusPatch constructs a set status apply patch.
func GenerateCertificateRequestPolicySetStatusPatch(policySet *policyapi.CertificateRequestPolicySet, status *policyapi.CertificateRequestPolicySetStatus) (*policyapi.CertificateRequestPolicySet, client.Patch, error) {
	object := &policyapi.CertificateRequestPolicySet{ObjectMeta: metav1.ObjectMeta{Name: policySet.Name, UID: policySet.UID, ResourceVersion: policySet.ResourceVersion}}
	configuration := &certificateRequestPolicySetStatusApplyConfiguration{
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{},
		Status:                       status,
	}
	configuration.WithName(policySet.Name).WithUID(policySet.UID).WithResourceVersion(policySet.ResourceVersion)
	configuration.WithKind("CertificateRequestPolicySet")
	configuration.WithAPIVersion(policyapi.SchemeGroupVersion.Identifier())
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return object, nil, err
	}
	return object, applyPatch{encoded}, nil
}

func GenerateCertificateRequestPolicyStatusPatch(
	policy *policyapi.CertificateRequestPolicy,
	status *policyapi.CertificateRequestPolicyStatus,
) (*policyapi.CertificateRequestPolicy, client.Patch, error) {
	// This object is used to deduce the name + unmarshall the return value in
	crp := &policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policy.Name, UID: policy.UID, ResourceVersion: policy.ResourceVersion},
	}

	// This object is used to render the patch
	b := &certificateRequestPolicyStatusStatusApplyConfiguration{
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{},
	}
	b.WithName(policy.Name).WithUID(policy.UID).WithResourceVersion(policy.ResourceVersion)
	b.WithKind(policyapi.CertificateRequestPolicyKind)
	b.WithAPIVersion(policyapi.SchemeGroupVersion.Identifier())
	b.Status = status

	encodedPatch, err := json.Marshal(b)
	if err != nil {
		return crp, nil, err
	}

	return crp, applyPatch{encodedPatch}, nil
}

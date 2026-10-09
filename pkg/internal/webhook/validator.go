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

package webhook

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sort"

	"github.com/go-logr/logr"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/internal/util"
)

// validator validates against policy.cert-manager.io resources.
type validator struct {
	log              logr.Logger
	enablePolicySets bool

	registeredPlugins []string
	webhooks          []approver.Webhook
}

var _ admission.Validator[*policyapi.CertificateRequestPolicy] = &validator{}

func (v *validator) ValidateCreate(ctx context.Context, obj *policyapi.CertificateRequestPolicy) (admission.Warnings, error) {
	if !v.enablePolicySets && obj.Spec.PolicySetRef != nil {
		return nil, field.Forbidden(field.NewPath("spec", "policySetRef"), "policy sets are disabled")
	}
	return v.validate(ctx, obj)
}

func (v *validator) ValidateUpdate(ctx context.Context, oldObj, newObj *policyapi.CertificateRequestPolicy) (admission.Warnings, error) {
	if !v.enablePolicySets && newObj.Spec.PolicySetRef != nil && !reflect.DeepEqual(oldObj.Spec.PolicySetRef, newObj.Spec.PolicySetRef) {
		return nil, field.Forbidden(field.NewPath("spec", "policySetRef"), "policy sets are disabled")
	}
	return v.validate(ctx, newObj)
}

func (v *validator) ValidateDelete(_ context.Context, _ *policyapi.CertificateRequestPolicy) (admission.Warnings, error) {
	// always allow deletes
	return nil, nil
}

// certificateRequestPolicy validates the given CertificateRequestPolicy with
// the base validations, along with all webhook validations registered.
func (v *validator) validate(ctx context.Context, policy *policyapi.CertificateRequestPolicy) (admission.Warnings, error) {
	var (
		fieldErrs field.ErrorList
		warnings  admission.Warnings
		fldPath   = field.NewPath("spec")
	)

	// Ensure no plugin has been defined which is not registered.
	var unrecognisedNames []string
	for name := range policy.Spec.Plugins {
		if !slices.Contains(v.registeredPlugins, name) {
			unrecognisedNames = append(unrecognisedNames, name)
		}
	}

	if len(unrecognisedNames) > 0 {
		// Sort list so testing is deterministic.
		sort.Strings(unrecognisedNames)
		for _, name := range unrecognisedNames {
			fieldErrs = append(fieldErrs, field.NotSupported(fldPath.Child("plugins"), name, v.registeredPlugins))
		}
	}

	fieldErrs = append(fieldErrs, util.ValidatePolicySelector(&policy.Spec.Selector, fldPath.Child("selector"))...)

	allAllowed := true
	for _, webhook := range v.webhooks {
		response, err := webhook.Validate(ctx, policy)
		if err != nil {
			return nil, err
		}
		if !response.Allowed {
			fieldErrs = append(fieldErrs, response.Errors...)

			allAllowed = false
		}
		warnings = append(warnings, response.Warnings...)
	}

	var errs []error

	if aggregateError := fieldErrs.ToAggregate(); aggregateError != nil {
		errs = append(errs, aggregateError.Errors()...)
	}

	// do not allow a CertificateRequestPolicy if it was not
	// allowed by a plugin that did not set any errors
	// TODO: when webhooks implement Name() method, provide a plugin name
	if !allAllowed && len(errs) == 0 {
		errs = append(errs, errors.New("a plugin did not allow the CertificateRequest for unknown reasons"))
	}

	return warnings, utilerrors.NewAggregate(errs)
}

type policySetValidator struct {
	enabled bool
}

var _ admission.Validator[*policyapi.CertificateRequestPolicySet] = &policySetValidator{}

func (validator *policySetValidator) ValidateCreate(_ context.Context, policySet *policyapi.CertificateRequestPolicySet) (admission.Warnings, error) {
	if !validator.enabled {
		return nil, field.Forbidden(field.NewPath("spec"), "policy sets are disabled")
	}
	return nil, util.ValidatePolicySetSelector(policySet.Spec.Selector, field.NewPath("spec", "selector")).ToAggregate()
}

func (validator *policySetValidator) ValidateUpdate(ctx context.Context, oldSet, newSet *policyapi.CertificateRequestPolicySet) (admission.Warnings, error) {
	if !validator.enabled && reflect.DeepEqual(oldSet.Spec, newSet.Spec) {
		return nil, nil
	}
	return validator.ValidateCreate(ctx, newSet)
}

func (validator *policySetValidator) ValidateDelete(_ context.Context, _ *policyapi.CertificateRequestPolicySet) (admission.Warnings, error) {
	return nil, nil
}

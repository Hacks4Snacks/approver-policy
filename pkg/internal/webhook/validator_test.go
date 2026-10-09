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
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog/v2/ktesting"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	fakeapprover "github.com/cert-manager/approver-policy/pkg/approver/fake"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

func TestPolicySetAdmission(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(), testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		filepath.Join("..", "..", "..", "deploy", "crds"))
	server := httptest.NewTLSServer(admission.WithValidator(policyapi.GlobalScheme, &policySetValidator{enabled: true}))
	t.Cleanup(server.Close)
	configuration := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-set-validation"},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name: "policysets.policy.cert-manager.io",
			ClientConfig: admissionv1.WebhookClientConfig{
				URL:      new(server.URL),
				CABundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
			},
			Rules: []admissionv1.RuleWithOperations{{
				Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
				Rule:       admissionv1.Rule{APIGroups: []string{"policy.cert-manager.io"}, APIVersions: []string{"v1alpha1"}, Resources: []string{"certificaterequestpolicysets"}},
			}},
			AdmissionReviewVersions: []string{"v1"}, FailurePolicy: new(admissionv1.Fail), SideEffects: new(admissionv1.SideEffectClassNone),
		}},
	}
	require.NoError(t, env.AdminClient.Create(t.Context(), configuration))
	invalid := &policyapi.CertificateRequestPolicySet{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-selector"},
		Spec: policyapi.CertificateRequestPolicySetSpec{
			Policies: []policyapi.CertificateRequestPolicyReference{{Name: "service"}},
			Selector: &policyapi.CertificateRequestPolicySelector{Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
				MatchLabels: map[string]string{"invalid key": "value"},
			}},
		},
	}
	require.Eventually(t, func() bool {
		err := env.AdminClient.Create(t.Context(), invalid.DeepCopy(), client.DryRunAll)
		return err != nil && strings.Contains(err.Error(), "spec.selector.namespace.matchLabels")
	}, 10*time.Second, 50*time.Millisecond)
	require.ErrorContains(t, env.AdminClient.Create(t.Context(), invalid), "spec.selector.namespace.matchLabels")
	require.True(t, apierrors.IsNotFound(env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(invalid), &policyapi.CertificateRequestPolicySet{})))
	valid := invalid.DeepCopy()
	valid.Name = "valid-selector"
	valid.Spec.Selector.Namespace.MatchLabels = map[string]string{"team": "identity"}
	require.NoError(t, env.AdminClient.Create(t.Context(), valid))
	valid.Spec.Selector.Namespace.MatchLabels = map[string]string{"team": "invalid value"}
	require.ErrorContains(t, env.AdminClient.Update(t.Context(), valid), "spec.selector.namespace.matchLabels")
	var stored policyapi.CertificateRequestPolicySet
	require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(valid), &stored))
	assert.Equal(t, map[string]string{"team": "identity"}, stored.Spec.Selector.Namespace.MatchLabels)
}

func TestPolicySetAdmissionGateRollout(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(), testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		filepath.Join("..", "..", "..", "deploy", "crds"))
	var enabledBackend atomic.Bool
	setHandlers := map[bool]http.Handler{
		false: admission.WithValidator(policyapi.GlobalScheme, &policySetValidator{enabled: false}),
		true:  admission.WithValidator(policyapi.GlobalScheme, &policySetValidator{enabled: true}),
	}
	policyHandlers := map[bool]http.Handler{
		false: admission.WithValidator(policyapi.GlobalScheme, &validator{enablePolicySets: false}),
		true:  admission.WithValidator(policyapi.GlobalScheme, &validator{enablePolicySets: true}),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlers := setHandlers
		if request.URL.Path == "/policies" {
			handlers = policyHandlers
		}
		handlers[enabledBackend.Load()].ServeHTTP(writer, request)
	}))
	t.Cleanup(server.Close)
	configuration := &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "policy-set-rollout"}}
	for _, resource := range []struct{ name, path string }{
		{name: "certificaterequestpolicysets", path: "/sets"},
		{name: "certificaterequestpolicies", path: "/policies"},
	} {
		configuration.Webhooks = append(configuration.Webhooks, admissionv1.ValidatingWebhook{
			Name: resource.name + ".policy.cert-manager.io",
			ClientConfig: admissionv1.WebhookClientConfig{
				URL:      new(server.URL + resource.path),
				CABundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
			},
			Rules: []admissionv1.RuleWithOperations{{
				Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
				Rule:       admissionv1.Rule{APIGroups: []string{"policy.cert-manager.io"}, APIVersions: []string{"v1alpha1"}, Resources: []string{resource.name}},
			}},
			AdmissionReviewVersions: []string{"v1"}, FailurePolicy: new(admissionv1.Fail), SideEffects: new(admissionv1.SideEffectClassNone),
		})
	}
	require.NoError(t, env.AdminClient.Create(t.Context(), configuration))
	policySet := &policyapi.CertificateRequestPolicySet{
		ObjectMeta: metav1.ObjectMeta{Name: "services"},
		Spec: policyapi.CertificateRequestPolicySetSpec{
			Policies: []policyapi.CertificateRequestPolicyReference{{Name: "member"}},
			Selector: &policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
		},
	}
	member := &policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "member"},
		Spec: policyapi.CertificateRequestPolicySpec{
			PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: policySet.Name},
			Selector:     *policySet.Spec.Selector.DeepCopy(),
		},
	}
	for _, object := range []client.Object{policySet, member} {
		require.Eventually(t, func() bool {
			err := env.AdminClient.Create(t.Context(), object.DeepCopyObject().(client.Object), client.DryRunAll)
			return err != nil && strings.Contains(err.Error(), "policy sets are disabled")
		}, 10*time.Second, 50*time.Millisecond)
	}
	standalone := member.DeepCopy()
	standalone.Name = "standalone"
	standalone.Spec.PolicySetRef = nil
	require.NoError(t, env.AdminClient.Create(t.Context(), standalone))
	for _, enabled := range []bool{false, true, false, true} {
		enabledBackend.Store(enabled)
		for _, object := range []client.Object{policySet, member} {
			err := env.AdminClient.Create(t.Context(), object.DeepCopyObject().(client.Object), client.DryRunAll)
			if enabled {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "policy sets are disabled")
			}
		}
	}
	require.NoError(t, env.AdminClient.Create(t.Context(), policySet))
	require.NoError(t, env.AdminClient.Create(t.Context(), member))
	enabledBackend.Store(false)
	changedSet := policySet.DeepCopy()
	changedSet.Spec.Policies = append(changedSet.Spec.Policies, policyapi.CertificateRequestPolicyReference{Name: "another"})
	require.ErrorContains(t, env.AdminClient.Update(t.Context(), changedSet), "policy sets are disabled")
	changedMember := member.DeepCopy()
	changedMember.Spec.PolicySetRef.Name = "other-set"
	require.ErrorContains(t, env.AdminClient.Update(t.Context(), changedMember), "policy sets are disabled")
	var storedSet policyapi.CertificateRequestPolicySet
	var storedMember policyapi.CertificateRequestPolicy
	require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(policySet), &storedSet))
	require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(member), &storedMember))
	require.Equal(t, policySet.Spec, storedSet.Spec)
	require.Equal(t, member.Spec, storedMember.Spec)
	storedSet.Labels = map[string]string{"rollout": "paused"}
	require.NoError(t, env.AdminClient.Update(t.Context(), &storedSet))
	storedMember.Spec.PolicySetRef = nil
	require.NoError(t, env.AdminClient.Update(t.Context(), &storedMember))
	storedMember.Spec.PolicySetRef = &policyapi.CertificateRequestPolicySetReference{Name: policySet.Name}
	require.ErrorContains(t, env.AdminClient.Update(t.Context(), &storedMember), "policy sets are disabled")
	enabledBackend.Store(true)
	require.NoError(t, env.AdminClient.Update(t.Context(), &storedMember))
	require.NoError(t, env.AdminClient.Delete(t.Context(), policySet))
	storedMember = policyapi.CertificateRequestPolicy{}
	require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(member), &storedMember))
	require.Equal(t, policySet.Name, storedMember.Spec.PolicySetRef.Name)
}

func TestPolicySetValidation(t *testing.T) {
	for _, test := range []struct {
		name          string
		disabled      bool
		labels        map[string]string
		emptySelector bool
		wantErr       bool
	}{
		{name: "valid selector"},
		{name: "qualified label", labels: map[string]string{"example.com/team": "identity"}},
		{name: "empty label value", labels: map[string]string{"team": ""}},
		{name: "invalid label key", labels: map[string]string{"bad key": "value"}, wantErr: true},
		{name: "invalid label value", labels: map[string]string{"team": "bad value"}, wantErr: true},
		{name: "empty selector", emptySelector: true, wantErr: true},
		{name: "disabled", disabled: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			policySet := &policyapi.CertificateRequestPolicySet{
				Spec: policyapi.CertificateRequestPolicySetSpec{
					Policies: []policyapi.CertificateRequestPolicyReference{{Name: "member"}},
					Selector: &policyapi.CertificateRequestPolicySelector{Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: test.labels}},
				},
			}
			if test.emptySelector {
				policySet.Spec.Selector = nil
			}
			validator := &policySetValidator{enabled: !test.disabled}
			_, err := validator.ValidateCreate(t.Context(), policySet)
			assert.Equal(t, test.wantErr, err != nil, "%v", err)
			_, err = validator.ValidateDelete(t.Context(), policySet)
			require.NoError(t, err)
			if test.disabled {
				_, err = validator.ValidateUpdate(t.Context(), policySet, policySet.DeepCopy())
				require.NoError(t, err)
				updated := policySet.DeepCopy()
				updated.Spec.Policies = append(updated.Spec.Policies, policyapi.CertificateRequestPolicyReference{Name: "another"})
				_, err = validator.ValidateUpdate(t.Context(), policySet, updated)
				require.ErrorContains(t, err, "disabled")
			}
		})
	}
}

func TestPolicySetOptInValidation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			validator := &validator{enablePolicySets: enabled}
			standalone := &policyapi.CertificateRequestPolicy{Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			}}
			member := standalone.DeepCopy()
			member.Spec.PolicySetRef = &policyapi.CertificateRequestPolicySetReference{Name: "services"}
			_, err := validator.ValidateCreate(t.Context(), standalone)
			require.NoError(t, err)
			_, err = validator.ValidateCreate(t.Context(), member)
			assert.Equal(t, !enabled, err != nil)
			_, err = validator.ValidateUpdate(t.Context(), standalone, member)
			assert.Equal(t, !enabled, err != nil)
			_, err = validator.ValidateUpdate(t.Context(), member, member.DeepCopy())
			require.NoError(t, err)
			_, err = validator.ValidateUpdate(t.Context(), member, standalone)
			require.NoError(t, err)
		})
	}
}

func Test_validate(t *testing.T) {
	someError := field.Invalid(field.NewPath("spec"), "foo", "some error occurred")
	testObjectMeta := metav1.ObjectMeta{Name: "test-policy", ResourceVersion: "3"}
	testTypeMeta := metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"}
	notAllowedWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: false, Errors: field.ErrorList{someError}}, nil
	})
	notAllowedWebhookNoDetail := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: false}, nil
	})
	passingWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: true}, nil
	})
	warningsWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: true, Warnings: admission.Warnings{"some warning"}}, nil
	})
	failingWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{}, errors.New("some error")
	})
	tests := map[string]struct {
		crp               *policyapi.CertificateRequestPolicy
		webhooks          []approver.Webhook
		registeredPlugins []string

		expectedWarnings admission.Warnings
		expectedError    *string
	}{
		"if the CertificateRequestPolicy refers to a plugin that is not registered return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
				},
			},
			registeredPlugins: []string{"foo", "baz"},

			expectedError: new("[spec.plugins: Unsupported value: \"bar\": supported values: \"foo\", \"baz\", spec.selector: Required value: one of issuerRef or namespace must be defined, hint: `{}` on either matches everything]"),
		},
		"if neither issuer ref nor namespace are defined, return error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
				},
			},
			registeredPlugins: []string{"foo", "bar"},

			expectedError: new("spec.selector: Required value: one of issuerRef or namespace must be defined, hint: `{}` on either matches everything"),
		},
		"if an invalid namespace label selector is defined, return error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"$%234": "8dsdk"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},

			expectedError: new("spec.selector.namespace.matchLabels: Invalid value: {\"$%234\":\"8dsdk\"}: key: Invalid value: \"$%234\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"),
		},
		"if a registered webhook does not allow CertificateRequestPolicy, return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, notAllowedWebhook},

			expectedError: new("spec: Invalid value: \"foo\": some error occurred"),
		},
		"if a registered webhook errors when validating CertificateRequestPolicy, return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, failingWebhook},

			expectedError: new("some error"),
		},
		"if a registered webhook does not allow CertificteRequestPolicy without further detail, return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, notAllowedWebhookNoDetail},

			expectedError: new("a plugin did not allow the CertificateRequest for unknown reasons"),
		},
		"if a webhook validation returns warnings, add return them": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, warningsWebhook},
			expectedWarnings:  admission.Warnings{"some warning"},
		},
		"if a  CertificateRequestPolicy with a defined issuer ref passes validation, allow it": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook},
		},
		"if a  CertificateRequestPolicy with a defined namespace selector passes validation, allow it": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := &validator{log: ktesting.NewLogger(t, ktesting.DefaultConfig), webhooks: test.webhooks, registeredPlugins: test.registeredPlugins}
			gotWarnings, gotErr := v.validate(t.Context(), test.crp)
			if test.expectedError == nil && gotErr != nil {
				t.Errorf("unexpected error: %v", gotErr)
			} else if test.expectedError != nil && (gotErr == nil || *test.expectedError != gotErr.Error()) {
				t.Errorf("wants error: %v got: %v", *test.expectedError, gotErr)
			}
			assert.Equal(t, test.expectedWarnings, gotWarnings)
		})
	}
}

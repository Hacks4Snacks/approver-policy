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

package controllers

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2/ktesting"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	fakeapprover "github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/internal/controllers/ssa_client"
	"github.com/cert-manager/approver-policy/pkg/internal/util"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

func TestPolicyReadinessStatusPreconditions(t *testing.T) {
	environment := testenv.RunControlPlane(t, t.Context(), testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		filepath.Join("..", "..", "..", "deploy", "crds"))
	for _, change := range []string{"unchanged", "updated", "replaced"} {
		t.Run(change, func(t *testing.T) {
			original := &policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "readiness-" + change},
				Spec: policyapi.CertificateRequestPolicySpec{
					PolicySetRef: &policyapi.CertificateRequestPolicySetReference{Name: "services"},
					Selector:     policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				},
			}
			require.NoError(t, environment.AdminClient.Create(t.Context(), original))
			changed := false
			controller := &certificaterequestpolicies{
				client: environment.AdminClient, clock: fakeclock.NewFakeClock(time.Now()),
				log: ktesting.NewLogger(t, ktesting.DefaultConfig), recorder: events.NewFakeRecorder(4),
				reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(ctx context.Context, observed *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					if !changed && change != "unchanged" {
						changed = true
						updated := observed.DeepCopy()
						issuerName := "different-issuer"
						updated.Spec.Selector.IssuerRef.Name = &issuerName
						if change == "replaced" {
							require.NoError(t, environment.AdminClient.Delete(ctx, observed))
							updated.ObjectMeta = metav1.ObjectMeta{Name: observed.Name}
							updated.Status = policyapi.CertificateRequestPolicyStatus{}
							require.NoError(t, environment.AdminClient.Create(ctx, updated))
						} else {
							require.NoError(t, environment.AdminClient.Update(ctx, updated))
						}
					}
					return approver.ReconcilerReadyResponse{Ready: true}, nil
				})},
			}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(original)}
			_, err := controller.Reconcile(t.Context(), request)
			var current policyapi.CertificateRequestPolicy
			require.NoError(t, environment.AdminClient.Get(t.Context(), request.NamespacedName, &current))
			policySet := &policyapi.CertificateRequestPolicySet{
				ObjectMeta: metav1.ObjectMeta{Name: "services"},
				Spec: policyapi.CertificateRequestPolicySetSpec{
					Policies: []policyapi.CertificateRequestPolicyReference{{Name: current.Name}},
					Selector: &policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				},
			}
			if change != "unchanged" {
				require.Error(t, err)
				require.Empty(t, current.Status.Conditions)
				if change == "replaced" {
					require.NotEqual(t, original.UID, current.UID)
					require.Equal(t, original.Generation, current.Generation)
				} else {
					require.Equal(t, original.UID, current.UID)
					require.Greater(t, current.Generation, original.Generation)
				}
				status, _, _ := util.PolicySetReadiness(policySet, map[string]policyapi.CertificateRequestPolicy{current.Name: current})
				require.Equal(t, metav1.ConditionFalse, status)
				_, err = controller.Reconcile(t.Context(), request)
				require.NoError(t, environment.AdminClient.Get(t.Context(), request.NamespacedName, &current))
			}
			require.NoError(t, err)
			status, _, _ := util.PolicySetReadiness(policySet, map[string]policyapi.CertificateRequestPolicy{current.Name: current})
			require.Equal(t, metav1.ConditionTrue, status)
		})
	}
}

func TestPolicySetReadinessStatusPreconditions(t *testing.T) {
	environment := testenv.RunControlPlane(t, t.Context(), testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		filepath.Join("..", "..", "..", "deploy", "crds"))
	for _, change := range []string{"unchanged", "updated", "replaced"} {
		t.Run(change, func(t *testing.T) {
			original := &policyapi.CertificateRequestPolicySet{
				ObjectMeta: metav1.ObjectMeta{Name: "readiness-" + change},
				Spec: policyapi.CertificateRequestPolicySetSpec{
					Policies: []policyapi.CertificateRequestPolicyReference{{Name: "member"}},
					Selector: &policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				},
			}
			require.NoError(t, environment.AdminClient.Create(t.Context(), original))
			status := &policyapi.CertificateRequestPolicySetStatus{Conditions: []metav1.Condition{{
				Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: original.Generation,
				Reason: "Ready", Message: "All members are ready", LastTransitionTime: metav1.NewTime(time.Now().Truncate(time.Second)),
			}}}
			object, patch, err := ssa_client.GenerateCertificateRequestPolicySetStatusPatch(original, status)
			require.NoError(t, err)
			current := original.DeepCopy()
			if change != "unchanged" {
				current.Spec.Policies = append(current.Spec.Policies, policyapi.CertificateRequestPolicyReference{Name: "new-member"})
				if change == "replaced" {
					require.NoError(t, environment.AdminClient.Delete(t.Context(), original))
					current.ObjectMeta = metav1.ObjectMeta{Name: original.Name}
					require.NoError(t, environment.AdminClient.Create(t.Context(), current))
					require.NotEqual(t, original.UID, current.UID)
					require.Equal(t, original.Generation, current.Generation)
				} else {
					require.NoError(t, environment.AdminClient.Update(t.Context(), current))
				}
			}
			err = environment.AdminClient.Status().Patch(t.Context(), object, patch, client.FieldOwner("approver-policy"), client.ForceOwnership)
			if change != "unchanged" {
				require.Error(t, err)
				require.NoError(t, environment.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(current), current))
				require.Nil(t, current.Status)
				status.Conditions[0].ObservedGeneration = current.Generation
				object, patch, err = ssa_client.GenerateCertificateRequestPolicySetStatusPatch(current, status)
				require.NoError(t, err)
				err = environment.AdminClient.Status().Patch(t.Context(), object, patch, client.FieldOwner("approver-policy"), client.ForceOwnership)
			}
			require.NoError(t, err)
			require.NoError(t, environment.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(current), current))
			require.Equal(t, status, current.Status)
		})
	}
}

func Test_certificaterequestpolicies_Reconcile(t *testing.T) {
	const (
		policyName             = "test-policy"
		policyGeneration int64 = 999
	)

	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		existingObjects []runtime.Object
		reconcilers     []approver.Reconciler

		expResult      ctrl.Result
		expError       bool
		expStatusPatch *policyapi.CertificateRequestPolicyStatus
		expEvent       string
	}{
		"if policy doesn't exist, no nothing": {
			existingObjects: nil,
			expResult:       ctrl.Result{},
			expError:        false,
			expStatusPatch:  nil,
			expEvent:        "",
		},
		"if no reconcilers defined, always update ready status": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			expResult: ctrl.Result{},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if reconciler returns ready response, update to ready": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			})},
			expResult: ctrl.Result{},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if reconciler returns not ready response, update to ready": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}}, nil
			})},
			expResult: ctrl.Result{},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
		},
		"if reconciler returns error, return error": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{}, errors.New("this is an error")
			})},
			expResult:      ctrl.Result{},
			expError:       true,
			expStatusPatch: nil,
			expEvent:       "",
		},
		"if reconciler returns ready response with requeue and requeueAfter, update to ready and mark requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if reconciler returns ready response with just requeueAfter > 0, update to ready and mark requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if two reconcilers returns ready response with requeue and requeueAfter, update to ready and mark requeue with requeueAfter of smaller duration": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Minute}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if one reconciler returns ready response with requeue and requeueAfter but condition already exists, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if one reconciler returns not-ready response with requeue and requeueAfter but condition already exists, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
		},
		"if two reconcilers returns ready response with only one requeue and requeueAfter, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if two reconcilers returns not-ready response with requeue and requeueAfter exists, update with not ready requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("bar"), "also not allowed")}, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
		},
		"if two reconcilers returns ready and not-ready response with requeue and requeueAfter exists, update with not ready requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{RequeueAfter: time.Minute}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
		},
		"if one reconciler returns ready but the other errors, return error": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{}, errors.New("this is an error")
				}),
			},
			expResult:      ctrl.Result{},
			expError:       true,
			expStatusPatch: nil,
			expEvent:       "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(policyapi.GlobalScheme).
				WithRuntimeObjects(test.existingObjects...).
				Build()

			fakerecorder := events.NewFakeRecorder(1)

			c := &certificaterequestpolicies{
				log:         ktesting.NewLogger(t, ktesting.DefaultConfig),
				clock:       fixedclock,
				client:      fakeclient,
				recorder:    fakerecorder,
				reconcilers: test.reconcilers,
			}

			resp, policyPatch, err := c.reconcileStatusPatch(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: policyName}})
			var statusPatch *policyapi.CertificateRequestPolicyStatus
			if policyPatch != nil {
				statusPatch = &policyPatch.Status
			}
			if (err != nil) != test.expError {
				t.Errorf("unexpected error, exp=%t got=%v", test.expError, err)
			}

			if !apiequality.Semantic.DeepEqual(resp, test.expResult) {
				t.Errorf("unexpected Reconcile response, exp=%v got=%v", test.expResult, resp)
			}

			var event string
			select {
			case event = <-fakerecorder.Events:
			default:
			}
			if event != test.expEvent {
				t.Errorf("unexpected event, exp=%q got=%q", test.expEvent, event)
			}

			if !apiequality.Semantic.DeepEqual(statusPatch, test.expStatusPatch) {
				t.Errorf("unexpected Reconcile response, exp=%v got=%v", test.expStatusPatch, statusPatch)
			}
		})
	}
}

func Test_certificaterequestpolicies_setCondition(t *testing.T) {
	const policyGeneration int64 = 2

	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		existingConditions []metav1.Condition
		patchConditions    []metav1.Condition
		newCondition       metav1.Condition
		expectedConditions []metav1.Condition
	}{
		"no existing conditions should add the condition with time and gen to the policy": {
			existingConditions: []metav1.Condition{},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{{
				Type:               "A",
				Status:             metav1.ConditionTrue,
				Reason:             "B",
				Message:            "C",
				LastTransitionTime: fixedmetatime,
				ObservedGeneration: policyGeneration,
			}},
		},
		"an existing patch condition of different type should add a different condition with time and gen to the policy": {
			patchConditions: []metav1.Condition{{Type: "B"}},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration,
				},
			},
		},
		"an existing patch condition of the same type but different status should be replaced with new time if it has a different status": {
			patchConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionFalse,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration - 1,
				},
			},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration,
				},
			},
		},
		"an existing patch condition of the same type and status should be replaced with same time": {
			patchConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: policyGeneration - 1,
				},
			},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: policyGeneration,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := &certificaterequestpolicies{clock: fixedclock}
			c.setCondition(
				test.existingConditions,
				&test.patchConditions, // #nosec G601 -- False positive. See https://github.com/golang/go/discussions/56010
				policyGeneration,
				test.newCondition,
			)

			if !apiequality.Semantic.DeepEqual(test.patchConditions, test.expectedConditions) {
				t.Errorf("unexpected resulting conditions, exp=%v got=%v", test.expectedConditions, test.patchConditions)
			}
		})
	}
}

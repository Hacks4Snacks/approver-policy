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
	"crypto/x509"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/ktesting"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	fakeapprover "github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/approver/manager"
	fakemanager "github.com/cert-manager/approver-policy/pkg/approver/manager/fake"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

func TestPolicySetChangePredicate(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*policyapi.CertificateRequestPolicySet)
		want   bool
	}{
		{name: "status update", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Status = &policyapi.CertificateRequestPolicySetStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}}
		}},
		{name: "metadata update", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Labels = map[string]string{"team": "identity"}
		}},
		{name: "membership update", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.Generation++
		}, want: true},
		{name: "deletion starts", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			now := metav1.Now()
			policySet.DeletionTimestamp = &now
		}, want: true},
		{name: "identity changes", change: func(policySet *policyapi.CertificateRequestPolicySet) {
			policySet.UID = "recreated"
		}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := &policyapi.CertificateRequestPolicySet{ObjectMeta: metav1.ObjectMeta{Name: "services", UID: "original", Generation: 2}}
			updated := original.DeepCopy()
			test.change(updated)
			predicate := policySetChangePredicate()
			require.Equal(t, test.want, predicate.Update(event.UpdateEvent{ObjectOld: original, ObjectNew: updated}))
			require.True(t, predicate.Create(event.CreateEvent{Object: original}))
			require.True(t, predicate.Delete(event.DeleteEvent{Object: original}))
		})
	}
}

func TestPolicySetsDisabledWithoutCRD(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(), testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		filepath.Join("..", "..", "..", "deploy", "crds", "policy.cert-manager.io_certificaterequestpolicies.yaml"))
	var policySets policyapi.CertificateRequestPolicySetList
	require.True(t, meta.IsNoMatchError(env.AdminClient.List(t.Context(), &policySets)))
	ctx, cancel := context.WithCancel(t.Context())
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme: policyapi.GlobalScheme, Metrics: server.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: new(true)},
		Cache:      cache.Options{ReaderFailOnMissingInformer: true},
	})
	require.NoError(t, err)
	require.NoError(t, AddControllers(ctx, Options{Manager: mgr, Log: ktesting.NewLogger(t, ktesting.DefaultConfig)}))
	finished := make(chan error, 1)
	go func() { finished <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("controller manager did not stop")
		}
	})
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "policysets-disabled"}}
	require.NoError(t, env.AdminClient.Create(ctx, namespace))
	policy := &policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "standalone"},
		Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
			IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
		}},
	}
	require.NoError(t, env.AdminClient.Create(ctx, policy))
	csr, _, err := gen.CSR(x509.RSA, gen.SetCSRDNSNames("service.example.com"))
	require.NoError(t, err)
	request := gen.CertificateRequest("standalone",
		gen.SetCertificateRequestNamespace(namespace.Name),
		gen.SetCertificateRequestCSR(csr),
		gen.SetCertificateRequestIssuer(cmmeta.IssuerReference{Name: "issuer"}),
	)
	require.NoError(t, env.AdminClient.Create(ctx, request))
	require.Eventually(t, func() bool {
		var current cmapi.CertificateRequest
		return env.AdminClient.Get(ctx, client.ObjectKeyFromObject(request), &current) == nil && apiutil.CertificateRequestIsApproved(&current)
	}, 10*time.Second, 10*time.Millisecond)
}

func TestPolicySetRolloutLeaderHandoff(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(), testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		filepath.Join("..", "..", "..", "deploy", "crds"))
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "policy-set-rollout"}}
	require.NoError(t, env.AdminClient.Create(t.Context(), namespace))
	evaluator := fakeapprover.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, request *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
		if request.Name != "denied" && (policy.Name == "standalone" || policy.Name == "allow-member") {
			return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
		}
		return approver.EvaluationResponse{Result: approver.ResultDenied}, nil
	})
	startReplica := func(enabled bool) (ctrl.Manager, func()) {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
			Scheme: policyapi.GlobalScheme, Metrics: server.Options{BindAddress: "0"},
			Controller:     config.Controller{SkipNameValidation: new(true)},
			Cache:          cache.Options{ReaderFailOnMissingInformer: true},
			LeaderElection: true, LeaderElectionID: "policy.cert-manager.io",
			LeaderElectionNamespace: namespace.Name, LeaderElectionResourceLock: "leases",
			LeaderElectionReleaseOnCancel: true,
			LeaseDuration:                 new(3 * time.Second), RenewDeadline: new(2 * time.Second), RetryPeriod: new(500 * time.Millisecond),
		})
		require.NoError(t, err)
		require.NoError(t, AddControllers(ctx, Options{
			Manager: mgr, Log: klog.Background(), EnablePolicySets: enabled,
			Evaluators: []approver.Evaluator{evaluator},
		}))
		finished := make(chan error, 1)
		go func() { finished <- mgr.Start(ctx) }()
		stop := sync.OnceFunc(func() {
			cancel()
			select {
			case err := <-finished:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Error("rollout controller manager did not stop")
			}
		})
		t.Cleanup(stop)
		return mgr, stop
	}
	waitForLeader := func(mgr ctrl.Manager) {
		t.Helper()
		select {
		case <-mgr.Elected():
		case <-time.After(10 * time.Second):
			t.Fatal("replica did not acquire leadership")
		}
	}
	createPolicy := func(name, issuer, setName string) {
		t.Helper()
		policy := &policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
				IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{Name: new(issuer)},
			}},
		}
		if setName != "" {
			policy.Spec.PolicySetRef = &policyapi.CertificateRequestPolicySetReference{Name: setName}
		}
		require.NoError(t, env.AdminClient.Create(t.Context(), policy))
	}
	csr, _, err := gen.CSR(x509.RSA, gen.SetCSRDNSNames("service.example.com"))
	require.NoError(t, err)
	createRequest := func(name, issuer string) {
		t.Helper()
		request := gen.CertificateRequest(name, gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr), gen.SetCertificateRequestIssuer(cmmeta.IssuerReference{Name: issuer}))
		require.NoError(t, env.AdminClient.Create(t.Context(), request))
	}
	waitForDecision := func(name string, approved bool) cmapi.CertificateRequest {
		t.Helper()
		var request cmapi.CertificateRequest
		require.Eventually(t, func() bool {
			if err := env.AdminClient.Get(t.Context(), client.ObjectKey{Namespace: namespace.Name, Name: name}, &request); err != nil {
				return false
			}
			if approved {
				return apiutil.CertificateRequestIsApproved(&request)
			}
			return apiutil.CertificateRequestIsDenied(&request)
		}, 10*time.Second, 20*time.Millisecond)
		return request
	}
	assertPending := func(name string) {
		t.Helper()
		require.Never(t, func() bool {
			var request cmapi.CertificateRequest
			require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKey{Namespace: namespace.Name, Name: name}, &request))
			return apiutil.CertificateRequestIsApproved(&request) || apiutil.CertificateRequestIsDenied(&request)
		}, time.Second, 20*time.Millisecond)
	}

	disabledLeader, stopDisabledLeader := startReplica(false)
	waitForLeader(disabledLeader)
	disabledFollower, stopDisabledFollower := startReplica(false)
	createPolicy("standalone", "standalone-issuer", "")
	createRequest("approved", "standalone-issuer")
	approved := waitForDecision("approved", true)
	createRequest("denied", "standalone-issuer")
	denied := waitForDecision("denied", false)
	interruptedReplica, stopInterruptedReplica := startReplica(true)
	select {
	case <-interruptedReplica.Elected():
		t.Fatal("feature-enabled replica displaced the existing leader")
	default:
	}
	stopInterruptedReplica()
	createRequest("after-interruption", "standalone-issuer")
	waitForDecision("after-interruption", true)
	stopDisabledLeader()
	waitForLeader(disabledFollower)
	createRequest("after-disabled-handoff", "standalone-issuer")
	waitForDecision("after-disabled-handoff", true)

	enabledLeader, stopEnabledLeader := startReplica(true)
	stopDisabledFollower()
	waitForLeader(enabledLeader)
	enabledFollower, _ := startReplica(true)
	policySet := &policyapi.CertificateRequestPolicySet{
		ObjectMeta: metav1.ObjectMeta{Name: "services"},
		Spec: policyapi.CertificateRequestPolicySetSpec{
			Policies: []policyapi.CertificateRequestPolicyReference{{Name: "deny-member"}, {Name: "allow-member"}},
			Selector: &policyapi.CertificateRequestPolicySetSelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{Name: new("service-issuer")}},
		},
	}
	require.NoError(t, env.AdminClient.Create(t.Context(), policySet))
	createPolicy("deny-member", "service-issuer", policySet.Name)
	createPolicy("fallback", "service-issuer", "")
	require.Eventually(t, func() bool {
		var current policyapi.CertificateRequestPolicySet
		if err := env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(policySet), &current); err != nil || current.Status == nil {
			return false
		}
		condition := meta.FindStatusCondition(current.Status.Conditions, policyapi.ConditionTypeReady)
		return condition != nil && condition.Status == metav1.ConditionFalse && condition.Reason == "PolicyMissing"
	}, 10*time.Second, 20*time.Millisecond)
	createRequest("pending-across-handoff", "service-issuer")
	assertPending("pending-across-handoff")
	stopEnabledLeader()
	waitForLeader(enabledFollower)
	assertPending("pending-across-handoff")
	createPolicy("allow-member", "service-issuer", policySet.Name)
	waitForDecision("pending-across-handoff", true)
	for _, terminal := range []cmapi.CertificateRequest{approved, denied} {
		var current cmapi.CertificateRequest
		require.NoError(t, env.AdminClient.Get(t.Context(), client.ObjectKeyFromObject(&terminal), &current))
		require.Equal(t, terminal.Status, current.Status)
	}
}

func Test_certificaterequests_Reconcile(t *testing.T) {
	const (
		requestName             = "test-request"
		requestGeneration int64 = 2
	)

	var (
		fixedTime                 = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime             = &metav1.Time{Time: fixedTime}
		fixedclock                = fakeclock.NewFakeClock(fixedTime)
		existingApprovedCondition = cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			LastTransitionTime: &metav1.Time{Time: fixedTime.Add(-time.Second)},
			Reason:             "policy.cert-manager.io",
			Message:            "policy is happy :)",
		}

		baseRequest = gen.CertificateRequest(requestName,
			gen.SetCertificateRequestTypeMeta(metav1.TypeMeta{
				Kind:       "CertificateRequest",
				APIVersion: "cert-manager.io/v1",
			}),
			func(cr *cmapi.CertificateRequest) {
				cr.ResourceVersion = "999"
			},
			gen.SetCertificateRequestNamespace(gen.DefaultTestNamespace),
		)
	)

	tests := map[string]struct {
		existingObjects []runtime.Object
		manager         manager.Interface

		expResult      ctrl.Result
		expError       bool
		expStatusPatch *cmapi.CertificateRequestStatus
		expEvent       string
	}{
		"if request doesn't exist, no nothing": {
			existingObjects: nil,
			expResult:       ctrl.Result{},
			expError:        false,
			expStatusPatch:  nil,
			expEvent:        "",
		},
		"if request is already approved, do nothing": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestStatusCondition(existingApprovedCondition))},
			expResult:      ctrl.Result{},
			expError:       false,
			expStatusPatch: nil,
			expEvent:       "",
		},
		"if manager review returns an error, fire event and return an error": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Message: "a review error"}, errors.New("this is an error")
			}),
			expResult:      ctrl.Result{},
			expError:       true,
			expStatusPatch: nil,
			expEvent:       "Warning EvaluationError approver-policy failed to review the request and will retry",
		},
		"if manager review returns an empty response, fire event and return a re-queue response": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{}, nil
			}),
			expResult:      ctrl.Result{RequeueAfter: time.Second * 5},
			expError:       false,
			expStatusPatch: nil,
			expEvent:       "Warning UnknownResponse Policy returned an unknown result. This is a bug. Please check the approver-policy logs and file an issue",
		},
		"if manager review returns an unknown response, fire event and return a re-queue response": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: 5, Message: "unknown result"}, nil
			}),
			expResult:      ctrl.Result{RequeueAfter: time.Second * 5},
			expError:       false,
			expStatusPatch: nil,
			expEvent:       "Warning UnknownResponse Policy returned an unknown result. This is a bug. Please check the approver-policy logs and file an issue",
		},
		"if manager review returns an unprocessed response, fire event and do nothing": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: manager.ResultUnprocessed, Message: "unprocessed result"}, nil
			}),
			expResult:      ctrl.Result{},
			expError:       false,
			expStatusPatch: nil,
			expEvent:       "Normal Unprocessed No approval decision is available; waiting for applicable policies or policy sets",
		},
		"if policy sets are pending, schedule fallback reevaluation": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: manager.ResultUnprocessed, RequeueAfter: time.Minute}, nil
			}),
			expResult: ctrl.Result{RequeueAfter: time.Minute},
			expEvent:  "Normal Unprocessed No approval decision is available; waiting for applicable policies or policy sets",
		},
		"if manager review returns denied, fire event and update request with denied": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: manager.ResultDenied, Message: "denied due to some violation"}, nil
			}),
			expResult: ctrl.Result{},
			expError:  false,
			expStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionDenied,
						Status:             cmmeta.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "policy.cert-manager.io",
						Message:            "denied due to some violation",
					},
				},
			},
			expEvent: "Warning Denied denied due to some violation",
		},
		"if manager review returns true, fire event and update request with approved": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: manager.ResultApproved, Message: "policy is happy :)"}, nil
			}),
			expResult: ctrl.Result{},
			expError:  false,
			expStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionApproved,
						Status:             cmmeta.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "policy.cert-manager.io",
						Message:            "policy is happy :)",
					},
				},
			},
			expEvent: "Normal Approved policy is happy :)",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(policyapi.GlobalScheme).
				WithRuntimeObjects(test.existingObjects...).
				Build()

			fakerecorder := events.NewFakeRecorder(1)

			c := &certificaterequests{
				client:   fakeclient,
				recorder: fakerecorder,
				manager:  test.manager,
				log:      ktesting.NewLogger(t, ktesting.DefaultConfig),
				clock:    fixedclock,
			}

			resp, statusPatch, err := c.reconcileStatusPatch(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: gen.DefaultTestNamespace, Name: requestName}})
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

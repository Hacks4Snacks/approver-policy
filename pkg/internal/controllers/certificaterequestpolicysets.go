package controllers

import (
	"context"
	"fmt"
	"reflect"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/internal/controllers/ssa_client"
	"github.com/cert-manager/approver-policy/pkg/internal/util"
)

const policySetMemberIndex = "spec.policies.name"

type certificaterequestpolicysets struct {
	client client.Client
	clock  clock.Clock
}

func addCertificateRequestPolicySetController(ctx context.Context, opts Options) error {
	if err := opts.Manager.GetFieldIndexer().IndexField(ctx, &policyapi.CertificateRequestPolicySet{}, policySetMemberIndex, func(object client.Object) []string {
		policySet := object.(*policyapi.CertificateRequestPolicySet)
		var names []string
		for _, reference := range policySet.Spec.Policies {
			names = append(names, reference.Name)
		}
		return names
	}); err != nil {
		return fmt.Errorf("failed to index policy set membership: %w", err)
	}
	apiClient := opts.Manager.GetClient()
	enqueueSets := func(ctx context.Context, object client.Object) []reconcile.Request {
		var policySets policyapi.CertificateRequestPolicySetList
		if err := apiClient.List(ctx, &policySets, client.MatchingFields{policySetMemberIndex: object.GetName()}); err != nil {
			opts.Log.Error(err, "failed to enqueue policy sets; periodic reconciliation will retry")
			return nil
		}
		requests := make([]reconcile.Request, 0, len(policySets.Items))
		for _, policySet := range policySets.Items {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: policySet.Name}})
		}
		return requests
	}
	return ctrl.NewControllerManagedBy(opts.Manager).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.CertificateRequestPolicyMaxConcurrentReconciles}).
		For(&policyapi.CertificateRequestPolicySet{}, builder.WithPredicates(policySetChangePredicate())).
		Watches(&policyapi.CertificateRequestPolicy{}, handler.EnqueueRequestsFromMapFunc(enqueueSets)).
		Complete(&certificaterequestpolicysets{client: apiClient, clock: clock.RealClock{}})
}

func (c *certificaterequestpolicysets) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var policySet policyapi.CertificateRequestPolicySet
	if err := c.client.Get(ctx, request.NamespacedName, &policySet); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	byName := make(map[string]policyapi.CertificateRequestPolicy, len(policySet.Spec.Policies))
	for _, reference := range policySet.Spec.Policies {
		var policy policyapi.CertificateRequestPolicy
		if err := c.client.Get(ctx, client.ObjectKey{Name: reference.Name}, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return ctrl.Result{}, fmt.Errorf("failed to read policy set member %q: %w", reference.Name, err)
		}
		byName[reference.Name] = policy
	}
	status, reason, message := util.PolicySetReadiness(&policySet, byName)
	updated := policySet.Status.DeepCopy()
	if updated == nil {
		updated = &policyapi.CertificateRequestPolicySetStatus{}
	}
	meta.SetStatusCondition(&updated.Conditions, metav1.Condition{
		Type: policyapi.ConditionTypeReady, Status: status, Reason: reason, Message: message,
		ObservedGeneration: policySet.Generation, LastTransitionTime: metav1.NewTime(c.clock.Now()),
	})
	if !reflect.DeepEqual(updated, policySet.Status) {
		object, patch, err := ssa_client.GenerateCertificateRequestPolicySetStatusPatch(&policySet, updated)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := c.client.Status().Patch(ctx, object, patch, client.FieldOwner("approver-policy"), client.ForceOwnership); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to patch policy set readiness: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

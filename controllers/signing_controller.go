package controllers

import (
	"context"

	"github.com/go-logr/logr"
	capi "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/webhook-operator/api"
)

// ApprovalReconciler will attempt to automatically approve CSRs that are
// identified as being referenced by a
type SigningReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme

	// SignerName is the name of the 'signer' used to denote CSRs that should
	// be signed by this signer.
	SignerName string
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=update
func (r *SigningReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("certificatesigningrequests", req.NamespacedName)

	csr := capi.CertificateSigningRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, &csr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Fast-path for non-approved requested
	if !api.IsCertificateRequestApproved(&csr) {
		return ctrl.Result{}, nil
	}

	// Ignore all requests if they don't specify signerName
	if csr.Spec.SignerName == nil {
		log.Info("spec.signerName field not set on CSR resource, this indicates the Kubernetes apiserver version is not 1.18+")
		return ctrl.Result{}, nil
	}

	// Ensure the signerName is one we should act upon
	if *csr.Spec.SignerName != api.WebhookServingSignerName {
		log.V(2).Info("Unrecognised spec.signerName, ignoring", "signerName", *csr.Spec.SignerName)
		return ctrl.Result{}, nil
	}

	x509Cr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		log.Error(err, "Failed to parse spec.request on CSR resource")
		return ctrl.Result{}, nil
	}

	if !isWebhookServingCSR(log, csr.Spec, x509Cr) {
		log.Info("CSR requests invalid parameters for this signer type")
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

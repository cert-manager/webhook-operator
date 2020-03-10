package controllers

import (
	"github.com/go-logr/logr"
	capi "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)


// RootCAReconciler will manage a Secret resource containing the root CA used
// to sign webhook generated webhook certificates.
type RootCAReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme

	// SignerName is the name of the 'signer' used to denote CSRs that should
	// be signed by this signer.
	SignerName string
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
func (r *RootCAReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func (r *RootCAReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capi.CertificateSigningRequest{}).WithEventFilter()
		Complete(r)
}

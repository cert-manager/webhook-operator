module github.com/cert-manager/webhook-operator

go 1.13

require (
	github.com/go-logr/logr v0.1.0
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	k8s.io/api v0.18.0-beta.1
	k8s.io/apimachinery v0.18.0-beta.1
	k8s.io/client-go v0.18.0-beta.1
	sigs.k8s.io/controller-runtime v0.4.0
)

replace k8s.io/api => k8s.io/api v0.0.0-20200303042250-8661bc967ba8

replace sigs.k8s.io/controller-runtime => github.com/munnerz/controller-runtime v0.1.8-0.20200303205705-7526607f5d91

module github.com/ns1/cert-manager-webhook-constellix

go 1.15

require (
	github.com/Constellix/constellix-go-client v1.0.12
	github.com/jetstack/cert-manager v0.13.0
	k8s.io/apiextensions-apiserver v0.17.0
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v0.17.0
)

replace github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.4

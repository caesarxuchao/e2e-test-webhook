build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o webhook .
	docker build --no-cache -t gcr.io/kubernetes-e2e-test-images/k8s-sample-admission-webhook-amd64:1.8v1 .

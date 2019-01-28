docker:
	docker build -t svc-shader .

container-build:
	gcloud container builds submit . --config=cloudbuild.yaml
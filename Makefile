
GOPATH:=$(shell go env GOPATH)

.PHONY: build
build: 
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static" -s -w' -o pse main.go 

.PHONY: test
test:
	go test -v ./... -cover

.PHONY: docker
docker: 
	
	docker build . -t pse:latest --ssh default

#--progress=plain
.PHONY: push
push: docker
	aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws/i1j1q8l2
	export IMAGES_TO_DELETE=$$( aws ecr list-images --region us-east-1 --repository-name pse --filter "tagStatus=UNTAGGED" --query 'imageIds[*]' --output json ) ;\
	aws ecr batch-delete-image --region us-east-1 --repository-name pse --image-ids "$${IMAGES_TO_DELETE}" || true 
	docker tag pse:latest public.ecr.aws/i1j1q8l2/pse-public:latest
	docker push public.ecr.aws/i1j1q8l2/pse-public:latest


.PHONY: run
run:
	micro run --env_vars "NATSURL=invisi-nats"  .

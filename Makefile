.SILENT:

test:
	go test ./test

run:
	go run ./cmd/main.go

dBuild:
	docker build -t forum .

dRun: docBuild
	docker run -it -p 8080:8080 forum

dORun: docBuild
	docker run -p 8081:8080 forum

dShow:
	docker images
dStop:
	docker stop $$(docker ps -a -q)

dDelete:
	docker rm $$(docker ps -a -q)

dDeleteImages:  
	docker rmi $$(docker images -q)

dClearAll:
	docker system prune -a

null:
	@:

docker-build: check-version
	@echo Building Rusty Hogs version: $(VERSION)
	docker build --tag rust-builder -f Dockerfile.build .
	docker build --tag wetfeet2000/ankamali_hog:$(VERSION) --build-arg HOG=ankamali -f Dockerfile.hog .
	docker build --tag wetfeet2000/berkshire_hog:$(VERSION) --build-arg HOG=berkshire -f Dockerfile.hog .
	docker build --tag wetfeet2000/choctaw_hog:$(VERSION) --build-arg HOG=choctaw -f Dockerfile.hog .
	docker build --tag wetfeet2000/duroc_hog:$(VERSION) --build-arg HOG=duroc -f Dockerfile.hog .
	docker build --tag wetfeet2000/essex_hog:$(VERSION) --build-arg HOG=essex -f Dockerfile.hog .
	docker build --tag wetfeet2000/gottingen_hog:$(VERSION) --build-arg HOG=gottingen -f Dockerfile.hog .
	docker build --tag wetfeet2000/hante_hog:$(VERSION) --build-arg HOG=hante -f Dockerfile.hog .

docker-save: check-version
	docker image save -o images.tar \
	wetfeet2000/ankamali_hog:$(VERSION) \
	wetfeet2000/berkshire_hog:$(VERSION) \
	wetfeet2000/choctaw_hog:$(VERSION) \
	wetfeet2000/duroc_hog:$(VERSION) \
	wetfeet2000/essex_hog:$(VERSION) \
	wetfeet2000/gottingen_hog:$(VERSION) \
	wetfeet2000/hante_hog:$(VERSION)

docker-load:
	docker load -i images.tar

docker-publish: check-version
	docker push wetfeet2000/ankamali_hog:$(VERSION)
	docker push wetfeet2000/berkshire_hog:$(VERSION)
	docker push wetfeet2000/choctaw_hog:$(VERSION)
	docker push wetfeet2000/duroc_hog:$(VERSION)
	docker push wetfeet2000/essex_hog:$(VERSION)
	docker push wetfeet2000/gottingen_hog:$(VERSION)
	docker push wetfeet2000/hante_hog:$(VERSION)

check-version:
	@if test ! $(VERSION); then echo "VERSION is undefined"; exit 1; fi

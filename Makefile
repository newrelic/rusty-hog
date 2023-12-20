null:
	@:

docker-build:
	@echo Building Rusty Hog Docker Images
	docker build --tag rust-builder -f Dockerfile.builder .
	docker build --tag wetfeet2000/ankamali_hog --build-arg HOG=ankamali -f Dockerfile.hog .
	docker build --tag wetfeet2000/berkshire_hog --build-arg HOG=berkshire -f Dockerfile.hog .
	docker build --tag wetfeet2000/choctaw_hog --build-arg HOG=choctaw -f Dockerfile.hog .
	docker build --tag wetfeet2000/duroc_hog --build-arg HOG=duroc -f Dockerfile.hog .
	docker build --tag wetfeet2000/essex_hog --build-arg HOG=essex -f Dockerfile.hog .
	docker build --tag wetfeet2000/gottingen_hog --build-arg HOG=gottingen -f Dockerfile.hog .
	docker build --tag wetfeet2000/hante_hog --build-arg HOG=hante -f Dockerfile.hog .

docker-save:
	@echo Saving Rusty Hog Docker Images to archive
	docker image save -o images.tar \
	wetfeet2000/ankamali_hog \
	wetfeet2000/berkshire_hog \
	wetfeet2000/choctaw_hog \
	wetfeet2000/duroc_hog \
	wetfeet2000/essex_hog \
	wetfeet2000/gottingen_hog \
	wetfeet2000/hante_hog

docker-load:
	@echo Loading Rusty Hog Docker Images from archive
	docker load -i images.tar

docker-publish: check-version
	@echo Publishing Rusty Hog Docker Images version: $(VERSION)
	docker tag wetfeet2000/ankamali_hog:latest wetfeet2000/ankamali_hog:$(VERSION)
	docker tag wetfeet2000/berkshire_hog:latest wetfeet2000/berkshire_hog:$(VERSION)
	docker tag wetfeet2000/choctaw_hog:latest wetfeet2000/choctaw_hog:$(VERSION)
	docker tag wetfeet2000/duroc_hog:latest wetfeet2000/duroc_hog:$(VERSION)
	docker tag wetfeet2000/essex_hog:latest wetfeet2000/essex_hog:$(VERSION)
	docker tag wetfeet2000/gottingen_hog:latest wetfeet2000/gottingen_hog:$(VERSION)
	docker tag wetfeet2000/hante_hog:latest wetfeet2000/hante_hog:$(VERSION)
	docker push -a wetfeet2000/ankamali_hog
	docker push -a wetfeet2000/berkshire_hog
	docker push -a wetfeet2000/choctaw_hog
	docker push -a wetfeet2000/duroc_hog
	docker push -a wetfeet2000/essex_hog
	docker push -a wetfeet2000/gottingen_hog
	docker push -a wetfeet2000/hante_hog

check-version:
	@if test ! $(VERSION); then echo "VERSION is undefined"; exit 1; fi

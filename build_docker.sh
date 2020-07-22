docker build --tag wetfeet2000/ankamali_hog:$1 --build-arg HOG=ankamali .
docker push wetfeet2000/ankamali_hog:$1
docker build --tag wetfeet2000/berkshire_hog:$1 --build-arg HOG=berkshire .
docker push wetfeet2000/berkshire_hog:$1
docker build --tag wetfeet2000/choctaw_hog:$1 --build-arg HOG=choctaw .
docker push wetfeet2000/choctaw_hog:$1
docker build --tag wetfeet2000/duroc_hog:$1 --build-arg HOG=duroc .
docker push wetfeet2000/duroc_hog:$1
docker build --tag wetfeet2000/essex_hog:$1 --build-arg HOG=essex .
docker push wetfeet2000/essex_hog:$1
docker build --tag wetfeet2000/gottingen_hog:$1 --build-arg HOG=gottingen .
docker push wetfeet2000/gottingen_hog:$1

#!/bin/bash

cd qemu
# SKIP_DOCKER_BUILD=1 make docker-image-debian-hexagon-cross 2>&1
# ret=$?
# if [ $ret -ne 0 ]; then
# 	make docker-image-debian-hexagon-cross 2>&1
# fi

./scripts/archive-source.sh ../qemu.tar

cd ..
docker build -f hexagon.dockerfile -t rbtree/qemu-hexagon . --progress=plain
rm qemu.tar
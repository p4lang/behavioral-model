# SPDX-FileCopyrightText: 2017 Seth Fowler
#
# SPDX-License-Identifier: Apache-2.0

ARG PARENT_VERSION=latest-24
FROM p4lang/pi:${PARENT_VERSION}
LABEL maintainer="P4 Developers <p4-dev@lists.p4.org>"

# Select the type of image we're building. Use `build` for a normal build, which
# is optimized for image size. Use `test` if this image will be used for
# testing; in this case, the source code and build-only dependencies will not be
# removed from the image.
ARG IMAGE_TYPE=build

ARG CC=gcc
ARG CXX=g++
ARG GCOV=
ARG sswitch_grpc=yes

ENV BM_DEPS build-essential \
            clang \
            cmake \
            curl \
            git \
            lcov \
            libgmp-dev \
            libpcap-dev \
            libboost-dev \
            libboost-program-options-dev \
            libboost-system-dev \
            libboost-filesystem-dev \
            libboost-thread-dev \
            libjsoncpp-dev \
            libxxhash-dev \
            pkg-config
ENV BM_RUNTIME_DEPS libboost-program-options1.74.0 \
                    libboost-system1.74.0 \
                    libboost-filesystem1.74.0 \
                    libboost-thread1.74.0 \
                    libgmp10 \
                    libpcap0.8t64 \
                    libxxhash0 \
                    python3 \
                    python3-six \
                    python-is-python3

COPY . /behavioral-model/
WORKDIR /behavioral-model/
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && \
    apt-get install -qq --no-install-recommends $BM_DEPS $BM_RUNTIME_DEPS && \
    mkdir -p build && cd build && \
    if [ "$GCOV" != "" ]; then cmake -DWITH_PDFIXED=ON -DWITH_PI=ON -DWITH_STRESS_TESTS=ON -DENABLE_DEBUGGER=ON -DENABLE_COVERAGE=ON -DENABLE_WERROR=ON ..; fi && \
    if [ "$GCOV" = "" ]; then cmake -DWITH_PDFIXED=ON -DWITH_PI=ON -DWITH_STRESS_TESTS=ON -DENABLE_DEBUGGER=ON -DENABLE_WERROR=ON ..; fi && \
    cmake --build . -j$(nproc) && \
    cmake --install . && cd .. && \
    ldconfig && \
    (test "$IMAGE_TYPE" = "build" && \
      rm -rf /behavioral-model /var/cache/apt/* /var/lib/apt/lists/* && \
      echo 'Build image ready') || \
    (test "$IMAGE_TYPE" = "test" && \
      echo 'Test image ready')

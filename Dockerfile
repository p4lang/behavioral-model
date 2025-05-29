ARG PARENT_VERSION=latest
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

# Common dependencies for both build and runtime
ENV BM_DEPS automake \
            build-essential \
            clang-8 \
            clang-10 \
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
            libtool \
            pkg-config

ENV BM_RUNTIME_DEPS libboost-program-options1.71.0 \
                    libboost-system1.71.0 \
                    libboost-filesystem1.71.0 \
                    libboost-thread1.71.0 \
                    libgmp10 \
                    libpcap0.8 \
                    python3 \
                    python-is-python3

# CMake configuration options
ENV CMAKE_OPTS "-DWITH_PDFIXED=ON -DWITH_PI=ON -DWITH_STRESS_TESTS=ON -DENABLE_DEBUGGER=ON -DENABLE_WERROR=ON"

COPY . /behavioral-model/
WORKDIR /behavioral-model/

RUN apt-get update -qq && \
    apt-get install -qq --no-install-recommends $BM_DEPS $BM_RUNTIME_DEPS && \
    ./autogen.sh && \
    mkdir -p build && cd build && \
    cmake $CMAKE_OPTS ${GCOV:+-DENABLE_COVERAGE=ON} .. && \
    make -j$(nproc) && \
    make install && cd .. && \
    ldconfig && \
    if [ "$IMAGE_TYPE" = "build" ]; then \
        apt-get purge -qq $BM_DEPS && \
        apt-get autoremove --purge -qq && \
        rm -rf /behavioral-model /var/cache/apt/* /var/lib/apt/lists/* && \
        echo 'Build image ready'; \
    else \
        echo 'Test image ready'; \
    fi

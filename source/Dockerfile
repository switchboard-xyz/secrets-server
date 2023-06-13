FROM gramineproject/gramine

# install Azure DCAP library
RUN apt-get update
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get install -y \
    build-essential \
    clang \
    clang-10 \
    cmake \
    cracklib-runtime \
    dbus \
    debhelper \
    gdb \
    git \
    gramine \
    kmod \
    lsb-release \
    make \
    net-tools \
    nodejs \
    unzip \
    vim

RUN curl -fsSLo /usr/share/keyrings/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.asc] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | \
    tee /etc/apt/sources.list.d/msprod.list
RUN apt-get update
RUN apt-get install -y az-dcap-client libsgx-dcap-default-qpl libsgx-dcap-quote-verify-dev

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain 1.69.0
ENV PATH=$PATH:/root/.cargo/bin/

WORKDIR /app

COPY src /app/src
COPY lib /app/lib
COPY Cargo.toml /app/Cargo.toml

RUN --mount=type=cache,target=/root/.cargo/registry --mount=type=cache,target=/app/target cargo build && mv target/debug/secrets-server /app
EXPOSE 8080
CMD ["/app/secrets-server"]

# syntax=docker/dockerfile:1.7

# Base images are pinned by digest. Dependabot (docker ecosystem) keeps them current.
ARG GO_IMAGE=golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b
ARG RUNTIME_IMAGE=gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

# ---------------------------------------------------------------------------
# dev: everything needed to build, test and scan, used by the devcontainer.
# Go-based quality tools (golangci-lint, gosec, govulncheck, gremlins, nilaway,
# goimports, go-test-coverage) are pinned in tools/go.mod and run with
# scripts/tool.sh. The cross C toolchain for the other architecture lets
# goreleaser link static-PIE binaries for both amd64 and arm64.
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS dev

ARG TASK_VERSION=v3.54.0
ARG ACTIONLINT_VERSION=v1.7.12
ARG GORELEASER_VERSION=v2.19.0
ARG DELVE_VERSION=v1.27.2
ARG GITLEAKS_VERSION=v8.30.1
ARG SYFT_VERSION=v1.55.0
ARG COSIGN_VERSION=v3.1.4
ARG TRIVY_VERSION=0.76.1
ARG HADOLINT_VERSION=v2.15.1
ARG SEMGREP_VERSION=1.182.1
ARG PRECOMMIT_VERSION=4.7.0
ARG SSH_AUDIT_VERSION=3.9.0
ARG DEV_USER=vscode
ARG USER_UID=1000

ENV DEBIAN_FRONTEND=noninteractive \
    GOFLAGS=-mod=readonly \
    GOTOOLCHAIN=local \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git git-lfs gnupg jq make openssh-client \
      python3 python3-venv sudo unzip xz-utils \
 && case "$(dpkg --print-architecture)" in \
      amd64) apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
      arm64) apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;; \
    esac \
 && rm -rf /var/lib/apt/lists/*

# Go-installed tools, pinned. GOFLAGS is relaxed only for these installs.
RUN GOFLAGS="" GOBIN=/usr/local/bin go install \
      github.com/go-task/task/v3/cmd/task@${TASK_VERSION} \
 && GOFLAGS="" GOBIN=/usr/local/bin go install \
      github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION} \
 && GOFLAGS="" GOBIN=/usr/local/bin go install \
      github.com/goreleaser/goreleaser/v2@${GORELEASER_VERSION} \
 && GOFLAGS="" GOBIN=/usr/local/bin go install \
      github.com/go-delve/delve/cmd/dlv@${DELVE_VERSION} \
 && GOFLAGS="" GOBIN=/usr/local/bin go install \
      github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION} \
 && GOFLAGS="" GOBIN=/usr/local/bin go install \
      github.com/anchore/syft/cmd/syft@${SYFT_VERSION} \
 && GOFLAGS="" GOBIN=/usr/local/bin go install \
      github.com/sigstore/cosign/v3/cmd/cosign@${COSIGN_VERSION} \
 && rm -rf /go/pkg /root/.cache

# Release binaries, verified against the project's published checksums.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /tmp
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) trivy_arch=64bit; hl_arch=x86_64; hl_sha=c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507 ;; arm64) trivy_arch=ARM64; hl_arch=arm64; hl_sha=f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d ;; esac; \
    base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
    curl -fsSLO "$base/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
    curl -fsSLO "$base/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" trivy; \
    install -m 0755 trivy /usr/local/bin/trivy; \
    base="https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}"; \
    curl -fsSLO "$base/hadolint-Linux-${hl_arch}"; \
    echo "${hl_sha}  hadolint-Linux-${hl_arch}" | sha256sum -c -; \
    install -m 0755 "hadolint-Linux-${hl_arch}" /usr/local/bin/hadolint; \
    rm -rf /tmp/*
WORKDIR /

# Python tools in an isolated venv.
RUN python3 -m venv /opt/pytools \
 && /opt/pytools/bin/pip install \
      semgrep==${SEMGREP_VERSION} pre-commit==${PRECOMMIT_VERSION} ssh-audit==${SSH_AUDIT_VERSION} \
 && ln -s /opt/pytools/bin/semgrep /opt/pytools/bin/pre-commit /opt/pytools/bin/ssh-audit /usr/local/bin/

RUN useradd --create-home --uid ${USER_UID} --shell /bin/bash ${DEV_USER} \
 && echo "${DEV_USER} ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/${DEV_USER} \
 && chmod 0440 /etc/sudoers.d/${DEV_USER} \
 && mkdir -p /go/pkg /home/${DEV_USER}/.cache && chown -R ${DEV_USER}: /go /home/${DEV_USER}/.cache
USER ${DEV_USER}
WORKDIR /workspaces/naraen

# ---------------------------------------------------------------------------
# client: a developer's machine in a container, for trying the local stack
# with real clients. git, git-lfs and ssh, set up the way a developer would
# be: the public development keys in ~/.ssh (writer by default), the dev
# server's host key trusted, and its TLS certificate trusted by git.
# naraen-smoke runs scripts/smoke.sh. docker-compose.yml runs it as the
# service client.
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS client
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git git-lfs openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1000 --shell /bin/bash dev \
 && install -d -m 700 -o dev -g dev /home/dev/.ssh \
 && install -d -m 755 /usr/local/share/naraen/devkeys
COPY --chmod=644 test/testdata/devkeys/writer test/testdata/devkeys/reader \
     test/testdata/devkeys/tls.crt test/testdata/devkeys/ssh_host_ed25519_key.pub /usr/local/share/naraen/devkeys/
COPY --chmod=755 scripts/smoke.sh /usr/local/bin/naraen-smoke
ENV NARAEN_DEVKEYS=/usr/local/share/naraen/devkeys
USER 1000:1000
WORKDIR /home/dev
RUN install -m 600 "${NARAEN_DEVKEYS}/writer" "${NARAEN_DEVKEYS}/reader" ~/.ssh/ \
 && echo "[naraen]:2222 $(cut -d' ' -f1,2 "${NARAEN_DEVKEYS}/ssh_host_ed25519_key.pub")" > ~/.ssh/known_hosts \
 && printf 'Host naraen\n  Port 2222\n  User git\n  IdentityFile ~/.ssh/writer\n  IdentitiesOnly yes\n' > ~/.ssh/config \
 && git config --global http.sslCAInfo "${NARAEN_DEVKEYS}/tls.crt" \
 && git config --global lfs.locksverify false \
 && git config --global init.defaultBranch main \
 && git config --global user.name "Dev" \
 && git config --global user.email dev@example.invalid \
 && git lfs install
CMD ["sleep", "infinity"]

# ---------------------------------------------------------------------------
# build: static, position-independent, stripped binary.
# This is the project's one build recipe; .goreleaser.yaml (and with it
# `task build`) uses the same flags. Change both together.
# ---------------------------------------------------------------------------
# The stage runs on the build host and cross-compiles, so a multi-arch image
# build needs no emulation.
FROM --platform=${BUILDPLATFORM} ${GO_IMAGE} AS build
# CGO is on only so the external linker can emit a static-PIE (ASLR) binary
# that runs on distroless/static; netgo and osusergo keep glibc out of the code.
ENV CGO_ENABLED=1 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
ARG TARGETOS TARGETARCH BUILDARCH
RUN if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
      apt-get update \
      && case "${TARGETARCH}" in \
           amd64) apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;; \
           arm64) apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
           *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
         esac \
      && rm -rf /var/lib/apt/lists/*; \
    fi
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    case "${TARGETARCH}" in amd64) cc=x86_64-linux-gnu-gcc ;; arm64) cc=aarch64-linux-gnu-gcc ;; esac; \
    CC="${cc}" GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildmode=pie -tags netgo,osusergo \
      -ldflags "-s -w -linkmode=external -extldflags=-static-pie -X main.version=${VERSION}" -o /out/naraen ./cmd/naraen

# ---------------------------------------------------------------------------
# runtime: distroless, nonroot, no shell. The deployment binds 22 and 443 by
# granting only CAP_NET_BIND_SERVICE; the image itself listens on high ports.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# runtime-dev: the runtime image plus the public development configuration
# from test/testdata, for docker-compose.yml's naraen service. The files come
# through the build context rather than bind mounts, so compose behaves the
# same from inside the devcontainer, whose paths the Docker host cannot see.
# It is never released: runtime, the last stage, is the default target.
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime-dev
COPY --from=build /out/naraen /usr/local/bin/naraen
# --chmod also applies to the /etc/naraen directory it creates, which must stay
# searchable; the files are public development values, readable by anyone.
COPY --chmod=755 test/testdata/snapshot.json test/testdata/seaweedfs/aws-credentials \
     test/testdata/devkeys/ssh_host_ed25519_key test/testdata/devkeys/tls.crt test/testdata/devkeys/tls.key /etc/naraen/
ENV NARAEN_SSH_ADDR=:2222 NARAEN_HTTPS_ADDR=:8443
EXPOSE 2222 8443
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/naraen"]

FROM ${RUNTIME_IMAGE} AS runtime
COPY --from=build /out/naraen /usr/local/bin/naraen
ENV NARAEN_SSH_ADDR=:2222 NARAEN_HTTPS_ADDR=:8443
EXPOSE 2222 8443
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/naraen"]

# syntax=docker/dockerfile:1.7

FROM golang:1.25-bookworm AS go-builder

ARG KATANA_VERSION=v1.7.0
RUN GOBIN=/out go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}


FROM kalilinux/kali-rolling:latest

ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="Hermes competition web recon worker" \
      org.opencontainers.image.description="Scoped Nmap, HTTPX, Katana and Gobuster worker"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates gobuster httpx-toolkit nmap tini \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && mkdir -p /work /opt/recon-wordlists \
    && ln -s /usr/bin/httpx-toolkit /usr/local/bin/httpx

COPY --from=go-builder /out/katana /usr/local/bin/katana
COPY docker/wordlists/web-common.txt /opt/recon-wordlists/web-common.txt
COPY docker/wordlists/SECLISTS-COPYRIGHT /opt/recon-wordlists/SECLISTS-COPYRIGHT

RUN chmod 0755 /usr/local/bin/katana

WORKDIR /work

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/bash"]

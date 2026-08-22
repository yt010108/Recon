# syntax=docker/dockerfile:1.7

FROM kalilinux/kali-rolling:latest AS go-builder

ARG DEBIAN_FRONTEND=noninteractive
ARG WAYBACKURLS_VERSION=v0.1.0
ARG ASSETFINDER_VERSION=v0.1.0
ARG KATANA_VERSION=v1.7.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git golang-go \
    && mkdir -p /out \
    && GOBIN=/out go install github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION} \
    && GOBIN=/out go install github.com/tomnomnom/assetfinder@${ASSETFINDER_VERSION} \
    && GOBIN=/out go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}


FROM kalilinux/kali-rolling:latest AS parameth-builder

ARG DEBIAN_FRONTEND=noninteractive
ARG PARAMETH_COMMIT=8da6f27c071f00bc0bd26a565de474e7ab5baa42

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git libcrypt-dev python2 python2-dev \
    && curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py \
    && python2 /tmp/get-pip.py --disable-pip-version-check \
        "pip==20.3.4" "setuptools==44.1.1" "wheel==0.37.1" \
    && python2 -m pip install --disable-pip-version-check --no-cache-dir \
        --target /opt/python2-site \
        "numpy==1.16.6" "requests==2.27.1" "fuzzywuzzy==0.18.0" \
        "python-Levenshtein==0.12.2" \
    && git init /opt/parameth \
    && git -C /opt/parameth remote add origin https://github.com/maK-/parameth.git \
    && git -C /opt/parameth fetch --depth 1 origin ${PARAMETH_COMMIT} \
    && git -C /opt/parameth checkout --detach ${PARAMETH_COMMIT} \
    && python2 -c 'p="/opt/parameth/parameth.py"; lines=open(p).readlines(); lines[0]="#!/usr/bin/env python2"+chr(10); open(p,"w").writelines(lines)' \
    && python2 -c 'p="/opt/parameth/parameth.py"; s=open(p).read(); old="default="+chr(39)+"lists/all.txt"+chr(39); new="default="+chr(39)+"/opt/recon-wordlists/params-small.txt"+chr(39); assert old in s; open(p,"w").write(s.replace(old,new,1))'


FROM kalilinux/kali-rolling:latest

ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="Hermes web reconnaissance worker" \
      org.opencontainers.image.description="Bug-bounty web recon worker without Nuclei, Nmap, Metasploit, or full SecLists"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates chromium gobuster httpx-toolkit python2 subfinder amass tini \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && useradd --create-home --uid 10001 --shell /bin/bash recon \
    && mkdir -p /work /output /opt/recon-wordlists \
    && chown -R recon:recon /work /output

COPY --from=go-builder /out/waybackurls /usr/local/bin/waybackurls
COPY --from=go-builder /out/assetfinder /usr/local/bin/assetfinder
COPY --from=go-builder /out/katana /usr/local/bin/katana
COPY --from=parameth-builder /opt/parameth /opt/parameth
COPY --from=parameth-builder /opt/python2-site /opt/python2-site
COPY docker/wordlists/params-small.txt /opt/recon-wordlists/params-small.txt
COPY docker/wordlists/web-common.txt /opt/recon-wordlists/web-common.txt
COPY docker/wordlists/SECLISTS-COPYRIGHT /opt/recon-wordlists/SECLISTS-COPYRIGHT

RUN chmod 0755 /usr/local/bin/waybackurls /usr/local/bin/assetfinder /usr/local/bin/katana /opt/parameth/parameth.py \
    && ln -s /usr/bin/httpx-toolkit /usr/local/bin/httpx \
    && ln -s /opt/parameth/parameth.py /usr/local/bin/parameth

ENV PYTHONPATH=/opt/python2-site \
    HOME=/home/recon

USER recon
WORKDIR /work

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/bash"]

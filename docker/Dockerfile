FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive
ARG KALI_TOOLS="gobuster subfinder amass httpx-toolkit"
ARG WAYBACKURLS_VERSION="v0.1.0"
ARG ASSETFINDER_VERSION="v0.1.0"
ARG KATANA_VERSION="v1.7.0"
ARG PARAMETH_COMMIT="8da6f27c071f00bc0bd26a565de474e7ab5baa42"
ARG GOOHAK_COMMIT="815a31e487c5f76d1e9b28c0f982d4807459db7f"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ${KALI_TOOLS} \
        ca-certificates curl git golang-go xdg-utils \
        python2 python2-dev python3 libcrypt-dev build-essential \
        libglib2.0-0t64 libnss3 libnspr4 \
        libatk1.0-0t64 libatk-bridge2.0-0t64 libatspi2.0-0t64 \
        libcups2t64 libdrm2 libgbm1 libasound2t64 \
        libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libxkbcommon0 \
        libpango-1.0-0 libcairo2 \
    && curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py \
    && python2 /tmp/get-pip.py --disable-pip-version-check \
        "pip==20.3.4" "setuptools==44.1.1" "wheel==0.37.1" \
    && python2 -m pip install --disable-pip-version-check --no-cache-dir \
        "numpy==1.16.6" "requests==2.27.1" "fuzzywuzzy==0.18.0" \
        "python-Levenshtein==0.12.2" \
    && GOBIN=/usr/local/bin go install github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION} \
    && GOBIN=/usr/local/bin go install github.com/tomnomnom/assetfinder@${ASSETFINDER_VERSION} \
    && GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} \
    && git init /opt/parameth \
    && git -C /opt/parameth remote add origin https://github.com/maK-/parameth.git \
    && git -C /opt/parameth fetch --depth 1 origin ${PARAMETH_COMMIT} \
    && git -C /opt/parameth checkout --detach ${PARAMETH_COMMIT} \
    && git init /opt/goohak \
    && git -C /opt/goohak remote add origin https://github.com/1N3/Goohak.git \
    && git -C /opt/goohak fetch --depth 1 origin ${GOOHAK_COMMIT} \
    && git -C /opt/goohak checkout --detach ${GOOHAK_COMMIT} \
    && python2 -c 'p="/opt/parameth/parameth.py"; lines=open(p).readlines(); assert lines and lines[0].startswith("#!/usr/bin/env python"); lines[0]="#!/usr/bin/env python2"+chr(10); open(p,"w").writelines(lines)' \
    && python2 -c 'p="/opt/parameth/parameth.py"; s=open(p).read(); old="default="+chr(39)+"lists/all.txt"+chr(39); new="default="+chr(39)+"/opt/parameth/lists/all.txt"+chr(39); assert old in s; open(p,"w").write(s.replace(old,new,1))' \
    && python3 -c 'p="/opt/goohak/goohak"; s=open(p).read(); old="BROWSER=\"firefox\" # CHANGE TO DEFAULT BROWSER - FOR OSX, USE \"open\"."; new="BROWSER=\"${GOOHAK_BROWSER:-xdg-open}\""; assert old in s; open(p,"w").write(s.replace(old,new,1))' \
    && chmod 0755 /opt/parameth/parameth.py /opt/goohak/goohak \
    && ln -s /usr/bin/httpx-toolkit /usr/local/bin/httpx \
    && ln -s /opt/parameth/parameth.py /usr/local/bin/parameth \
    && ln -s /opt/parameth/parameth.py /usr/local/bin/parameth.py \
    && ln -s /opt/goohak/goohak /usr/local/bin/goohak \
    && rm -rf /var/lib/apt/lists/* /tmp/get-pip.py /root/.cache/go-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends seclists \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["/bin/bash"]

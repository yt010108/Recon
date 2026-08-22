# 설치 기록

## 2026-08-19

- Docker image pulled: `kalilinux/kali-rolling:latest`
- Container: `kali`
- Kali release: `2026.3`
- Installed package: `metasploit-framework`
- Package version: `6.5.0-0kali1`
- `msfconsole --version`: `Framework Version: 6.5.0-dev`
- Installed package: `wordlists`
- Wordlists package version: `2026.2.0`
- Wordlist files:
  - `/usr/share/wordlists/john.lst`
  - `/usr/share/wordlists/metasploit`
  - `/usr/share/wordlists/nmap.lst`
  - `/usr/share/wordlists/rockyou.txt.gz`
- Verified existing packages:
  - `nmap` `7.99+dfsg-1kali1`
  - `john` `1.9.0-Jumbo-1+git20211102-0kali11`

### 요청한 도구 설치

- APT packages installed:
  - `subfinder` `2.14.0-0kali1` — command `subfinder` (`v2.14.0`)
  - `httpx-toolkit` `1.9.0-0kali2` — command `httpx` via `/usr/local/bin/httpx` symlink
  - `gobuster` `3.8.2-1`
  - `nuclei` `3.11.0-0kali1` — command reports `v3.11.0`
- Go tools installed with Go `1.26.5`:
  - `waybackurls` `v0.1.0`
  - `katana` `v1.7.0`
- GitHub source tools:
  - `parameth` from `maK-/parameth` commit `8da6f27c071f00bc0bd26a565de474e7ab5baa42`
    - Python 2 runtime with pinned `numpy`, `requests`, `fuzzywuzzy`, and `python-Levenshtein` dependencies
    - explicit `python2` shebang added to the installed copy
    - default wordlist path changed to `/opt/parameth/lists/all.txt`
  - `goohak` from `1N3/Goohak` commit `815a31e487c5f76d1e9b28c0f982d4807459db7f`
    - command `goohak`, version `1.9`
    - browser command defaults to `xdg-open`; override with `GOOHAK_BROWSER`
- Verification performed:
  - all requested command paths resolve in the live `kali` container
  - `parameth --help` exits successfully
  - `goohak` no-argument usage output works
  - ProjectDiscovery, Gobuster, Nuclei, and Go module metadata were queried
- Installed package: `seclists` `2025.3-0kali1`
  - `/usr/share/seclists/Discovery/Web-Content/common.txt`
  - `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
  - `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- Updated Nuclei templates with `nuclei -ut`
  - Template version: `v10.4.7`
  - Template path: `/root/.local/nuclei-templates`
  - YAML template count probe: 13,510 files
- Reproducible build files updated:
  - `docker/Dockerfile`
  - `docker/compose.yaml`
  - `tools.yaml`

### HTTPX 웹 스크린샷 검증

- 로컬 OWASP Juice Shop `http://recon-juice-shop:3000`만 대상으로 테스트했다.
- HTTPX `v1.9.0`의 `-ss` headless screenshot 기능이 정상 동작했다.
- HTTPX가 `/root/.cache/rod/browser/chromium-1321438`에 약 533 MB Chromium
  스냅샷을 내려받았다.
- 브라우저 실행에 필요한 직접 런타임 패키지 17개와 전이 의존성 38개를 설치했다.
  다운로드 크기는 약 22.7 MB, 설치 후 추가 디스크 사용량은 약 91.6 MB였다.
- 캡처 결과는 `recon-harness/screenshots/juice-shop.png`에 저장했다.
- 재현용 `docker/Dockerfile`에는 직접 런타임 패키지를 추가했다. Chromium 캐시는 이미지에
  포함하지 않으므로 새 컨테이너에서는 첫 캡처 시 다시 내려받는다.

## 2026-08-22

- 리콘 이미지의 책임을 수집·프로빙·크롤링·탐색으로 제한했다.
- 재현용 `docker/Dockerfile`과 `docker/compose.yaml`에서 다음 도구를 제외했다:
  - `metasploit-framework`: 이후 별도 침투 테스트 이미지로 분리
  - `nuclei`: 이후 별도 검증 이미지로 분리
- 이미지 빌드 중 실행하던 `nuclei -ut` 템플릿 다운로드도 제거했다.
- Metasploit 제거로 더 이상 전이 설치되지 않는 `python3`를 Goohak 패치용 직접 의존성으로
  명시했다.
- 기존에 생성된 `kali` 컨테이너는 자동으로 변경되지 않는다. 새 이미지로 다시 빌드하고
  컨테이너를 재생성해야 런타임에서도 두 도구가 제거된다.
- `local/kali-security:latest` 재빌드 성공:
  - 이미지 ID: `sha256:016eaffd1d7a1ddb407f7f274e0ba19b1af5a830fcc96facbca51a4f48bf147d`
  - Docker 이미지 목록의 가상 크기: 약 5.47 GB
  - `msfconsole`, `nuclei` 명령 부재 확인
  - `metasploit-framework`, `nuclei` 패키지 부재 확인
  - subfinder, httpx, gobuster, waybackurls, assetfinder, katana, parameth, goohak 존재 확인

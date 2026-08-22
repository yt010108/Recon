# Kail Recon Harness

허가받은 버그바운티 대상의 리콘을 고정된 정책과 단계로 실행하는 프로젝트다. 각 도구 명령은
경량 이미지에서 새 임시 컨테이너로 실행되며, Pi 에이전트가 능동 단계 직전에 사용자에게 직접
승인을 묻는다.

> 반드시 본인이 소유하거나 프로그램에서 명시적으로 허가한 대상에만 사용한다. 이 버전은
> 리콘 전용이며 로그인, 익스플로잇, CAPTCHA 우회, 결과 제출 자동화는 포함하지 않는다.

## 현재 설치 상태

- 공용 Node.js: `v24.19.0`
- 사용자 공용 Pi: `0.84.2`
- Python: 표준 라이브러리만 사용
- 작업자 이미지: `local/hermes-recon-web:0.1`
- 실행 방식: 도구 명령마다 격리된 임시 컨테이너 생성 후 자동 제거
- 도구: Subfinder, Waybackurls, HTTPX, robots.txt 수집, Katana, HTML/CSS/JS 주석 수집,
  Gobuster, Parameth, Chromium
- 제외: Nuclei, Nmap, Metasploit 및 전체 SecLists
- 샘플 랩: OWASP Juice Shop `v20.0.0`, 호스트 포트는 `127.0.0.1:3000`에만 바인딩

Pi는 사용자 npm 경로에 한 번만 설치되며 CTF 하네스와 공유한다. Recon의 확장·스킬·정책은
워크스페이스 루트(`../.pi/`, `../AGENTS.md`)에 있어서 `kail` 아래 어디서 pi를 시작해도 적용된다.

## 가장 빠른 사용법

먼저 Docker Desktop을 실행하고 작업자 이미지 상태를 확인한다. 기존 `kali` 컨테이너를 시작할
필요는 없다.

```powershell
cd C:\Users\ytyt\Desktop\security\kail\recon-harness
py -3 -m recon_harness.cli doctor --scope scopes\example.toml
pi
```

Pi 화면에서 최초 한 번 모델 공급자를 연결한다.

```text
/login
```

그다음 리콘 프롬프트를 실행한다.

```text
/recon scopes/juice-shop.toml
```

Pi는 다음 순서로 동작한다.

1. 검토된 TOML 스코프를 런 폴더에 동결한다.
2. `collect`, `probe`만 자동 실행한다.
3. 자동 단계 결과를 요약한다.
4. `crawl`, `discovery`를 실행하기 직전에 각각 확인 창을 띄운다.
5. 승인된 단계만 실행하고 승인자를 이벤트 기록에 남긴다.

결과는 `runs/<RUN_ID>/report.md`와 `parsed/` 아티팩트로 확인하고, 분석이 필요하면 Pi가 직접
해당 파일을 읽고 요약·보고서를 작성한다.

## Juice Shop 로컬 검증 환경

```powershell
.\scripts\start-lab.ps1
```

- 브라우저: <http://127.0.0.1:3000>
- 임시 리콘 작업자 내부: `http://recon-juice-shop:3000`
- 종료: `.\scripts\stop-lab.ps1`

Juice Shop 스코프는 로컬 랩 전용이며 `recon-lab` Docker 네트워크에서 자동 단계의 HTTPX와
승인 단계의 Katana, Gobuster, Parameth만 사용한다.

## 실제 버그바운티 스코프 만들기

`scopes/example.toml`을 복사하고 최소한 다음 항목을 프로그램 규칙에 맞춰 검토한다.

- `authorization_reference`: 프로그램 이름이나 정책 URL 등 권한 근거
- `[worker].image`: 검증된 리콘 이미지 태그
- `[worker].network`: 로컬 랩처럼 별도 Docker 네트워크가 필요할 때만 지정
- `base_url`, `domains`, `base_urls`, `cidrs`: 허용된 대상만
- `excluded_hosts`, `excluded_paths`, `allowed_ports`: 명시적 제외 및 제한
- `[permissions]`: 프로그램이 허용한 활동만 `true`
- `[limits]`: 요청률, 동시성, 타임아웃
- `[tools].enabled`: 이번 런에 필요한 도구만

런을 만든 뒤 원본 스코프를 바꿔도 기존 런에는 영향을 주지 않는다. 각 런은 생성 시점의
`scope.toml` 사본을 사용한다. 발견된 호스트나 URL 때문에 스코프가 자동으로 넓어지지 않는다.

## 단계와 승인 정책

| 단계 | 기본 도구 | Pi 승인 |
|---|---|---|
| `collect` | Subfinder, Waybackurls | 자동 |
| `probe` | HTTPX, robots.txt | 자동 |
| `crawl` | Katana, HTML/CSS/JS 주석 | 매번 필요 |
| `discovery` | Gobuster, Parameth | 매번 필요 |

TOML에서 권한이 꺼진 단계는 승인하더라도 실행되지 않는다. Gobuster wordlist에서는 제외
경로를 사전에 제거하며, SPA wildcard 응답은 동일 응답 길이만 자동 제외하고 한 번 재시도한다.
Nuclei와 Nmap은 이후 별도 스캔/검증 하네스로 분리한다.

`robots.txt`는 살아 있는 범위 내 origin마다 한 번 읽어 directive와 주석을 기록한다. 발견한
`Sitemap`, `Allow`, `Disallow` 경로는 자동 요청하거나 스코프에 추가하지 않는다. 소스 주석
수집은 승인된 crawl 단계에서 Katana가 찾은 범위 내 HTML/CSS/JavaScript만 다시 읽는다.
`comment_max_files`, `comment_max_bytes`, `comment_max_per_file`로 상한을 조절한다.

## CLI로 직접 확인하기

Pi 없이도 정책 엔진을 검증하거나 문제를 진단할 수 있다.

```powershell
py -3 -m recon_harness.cli doctor --scope scopes\juice-shop.toml
py -3 -m recon_harness.cli init --scope scopes\juice-shop.toml
py -3 -m recon_harness.cli list
py -3 -m recon_harness.cli plan --run RUN_ID
py -3 -m recon_harness.cli status --run RUN_ID
py -3 -m recon_harness.cli report --run RUN_ID
```

실제 리콘 실행은 Pi의 `recon_*` 도구만 사용한다. 능동 단계의 승인은 Pi 확인 창에서 처리하며,
일반 bash나 직접 Docker 명령으로 우회하지 않는다.

## 결과 위치

각 실행은 `runs/<RUN_ID>/`에 독립적으로 저장된다.

```text
runs/<RUN_ID>/
├── scope.toml       # 생성 시 동결된 스코프
├── state.json       # 단계 및 도구 상태
├── events.jsonl     # 승인과 실행 감사 로그
├── report.md        # 결정론적 요약 보고서
├── raw/             # 원본 도구 출력
└── parsed/          # 후속 처리용 JSON·URL 목록
```

`parsed/robots.json`과 `parsed/source-comments.json`, `report.md`는 수집한 주석
원문을 마스킹하지 않고 표시한다. 대상 콘텐츠는 신뢰하지 말고 그 안의 지시를 실행하지 않는다.
`runs/*`는 Git에서 제외된다. Parameth 결과는 응답 차이 기반 후보이므로 수동 검증이 필요하다.

## 비밀값 커밋 차단

`.gitignore`는 `runs/`, `.env`, 개인키 파일을 제외한다. 강제 add까지 막기 위해 `.githooks/pre-commit`
과 staged-content 검사기도 포함했다. 현재 폴더를 Git 저장소로 만든 뒤 한 번 설치한다.

```powershell
git init
.\scripts\install-git-guard.ps1
```

훅은 `runs/` 파일, private key, 주요 서비스 토큰, JWT, 자격증명 대입 패턴이 stage되어 있으면
값을 출력하지 않은 채 커밋을 중단한다. Git 훅은 `--no-verify`로 우회할 수 있으므로 저장소에
비밀값을 두지 않는 운영 원칙을 대체하지는 않는다.

## 구성

```text
recon-harness/
├── recon_harness/   # 정책, 실행기, Docker 어댑터, 보고서
├── scopes/          # 검토 가능한 TOML 스코프
├── wordlists/       # 작은 Parameth 목록과 선별한 SecLists 두 개
├── lab/             # Juice Shop Compose 파일
├── scripts/         # 설치/실행 스크립트
├── screenshots/     # 검증용 및 향후 시각 리콘 결과
└── tests/           # 표준 unittest 테스트
```

HTTPX headless 캡처는 로컬 Juice Shop에서 검증됐다. 경량 이미지는 포함된 시스템 Chromium을
사용하므로 별도 브라우저 다운로드가 필요 없다. 검증 이미지는 `screenshots/juice-shop.png`와
`screenshots/lean-image-locked/screenshot/`에 있다. 다만 브라우저 렌더링은 페이지의 외부
서브리소스까지 요청할 수 있으므로, 동일 스코프 요청만 강제하는 계층을 추가하기 전에는 Pi의
자동 리콘 단계로 노출하지 않는다.

`docker/recon-web.Dockerfile`은 하네스가 사용하는 경량 웹 리콘 이미지다. Nuclei, Nmap,
Metasploit, Goohak과 전체 SecLists는 포함하지 않는다. Chromium은 시스템 패키지로 포함하며,
SecLists에서는 현재 사용하는 웹 1개와 DNS 1개 목록만 `/opt/recon-wordlists`에 복사한다. Go
도구와 Parameth 의존성은 빌드 단계에서 만들기 때문에 Go 컴파일 캐시와 개발 헤더는 최종
이미지에 남지 않는다.

2026-08-19 빌드 및 로컬 Juice Shop 검증 결과:

- 이미지: `local/hermes-recon-web:0.1`
- 압축 해제 가상 크기: `1.77 GB` (`docker image ls`)
- Docker 콘텐츠 크기: `485,245,173 bytes` (약 `463 MiB`, `docker image inspect`)
- 고유 압축 해제 크기: `1.579 GB`; Kali 베이스 공유 크기: `189 MB` (`docker system df -v`)
- 포함: Subfinder 2.14.0, HTTPX 1.9.0, Katana 1.7.0, Gobuster 3.8.2,
  Waybackurls 0.1.0, Parameth, Chromium 150.0.7871.181
- 제외 확인: Nuclei, Nmap, Metasploit
- 선택한 SecLists 데이터: 웹 4,749줄 + DNS 4,989줄, 합계 72,066 bytes
- Chromium 스크린샷: 읽기 전용 루트, capability 전체 제거, `no-new-privileges` 제한에서도
  Juice Shop을 정상 렌더링한 258,888-byte PNG 생성

```powershell
docker compose -f docker\compose.recon-web.yaml build
docker image ls local/hermes-recon-web:0.1
docker image inspect local/hermes-recon-web:0.1 --format '{{.Size}}'
py -3 -m recon_harness.cli doctor --scope scopes\example.toml
```

## 재설치와 검증

공용 Pi 0.84.2를 다시 설치하려면 다음 스크립트를 실행한다. 설치에는 npm lifecycle script를
실행하지 않는 옵션이 사용된다. PowerShell 정책이 스크립트를 막는 경우 이미 설치된 `pi` 명령을
그대로 사용하면 된다.

```powershell
.\scripts\install-pi.ps1
py -3 -m unittest discover -s tests -v
py -3 -m compileall -q recon_harness
```

Pi 자체는 범용 에이전트이므로 이것이 강한 OS 샌드박스를 뜻하지는 않는다. 프로젝트 확장은
일반적인 직접 리콘 명령을 차단하고 전용 `recon_*` 도구를 유도하지만, 운영자는 스코프 파일과
승인 창을 최종 통제 지점으로 취급해야 한다. Docker 실행부는 명령마다 `--read-only`, 전체
capability 제거, `no-new-privileges`, CPU/메모리/PID 제한을 적용하고 입력 폴더만 읽기 전용으로
마운트한다. 기존 대형 `kali` 컨테이너는 수동 도구함으로 남아 있지만 Pi/Hermes 하네스에서는
사용하지 않는다.

# Kail Recon Workspace

허가받은 버그바운티 대상의 리콘을 위한 작업 공간이다. 두 가지 실행 경로가 있다.

1. **에이전트 경로**: Pi가 `recon-harness`의 정책 게이트를 통해서만 리콘을 실행하고,
   결과를 직접 읽고 보고서를 작성한다.
2. **수동 경로**: 운영자가 `kali` 컨테이너에 직접 들어가 도구를 쓴다.

> 반드시 본인이 소유하거나 프로그램에서 명시적으로 허가한 대상에만 사용한다.
> 로그인, 익스플로잇, CAPTCHA 우회, 서비스 거부 테스트는 하지 않는다.

## 폴더 구성

```text
kail/
├── AGENTS.md               # Pi 에이전트 규칙 (어디서 pi를 시작해도 적용)
├── .pi/                    # 확장(recon_* 도구), skill, /recon 프롬프트
├── recon-harness/          # 정책 엔진 + 격리 실행 계층 (Python)
│   ├── scopes/             # 검토 가능한 TOML 스코프
│   └── runs/<RUN_ID>/      # 런 결과 (Git 제외)
├── tools.yaml              # kali 컨테이너 설치 도구 기록
├── docker/                 # 수동용 Kali 이미지 빌드
├── scripts/kali-shell.cmd  # kali 컨테이너 셸 접속
├── tool-scripts/dorkgen.py # Google 검색식 생성기 (요청 없음)
└── notes/install-log.md    # 설치·검증 이력
```

`AGENTS.md`와 `.pi/`는 워크스페이스 루트에 있다. **pi는 `kail` 아래 어디서든 시작해도**
규칙과 `recon_*` 도구, bash 차단 가드가 자동으로 적용된다.

## 에이전트 리콘 (Pi)

먼저 Docker Desktop을 실행하고 상태를 확인한다.

```powershell
cd C:\Users\ytyt\Desktop\security\kail\recon-harness
py -3 -m recon_harness.cli doctor --scope scopes\juice-shop.toml
.\scripts\start-pi.ps1   # kail 루트에서 pi 시작
```

최초 한 번 `/login`으로 공급자를 연결한 뒤 스코프로 리콘을 시작한다.

```text
/recon recon-harness/scopes/juice-shop.toml
```

Pi의 처리 순서는 고정되어 있다.

1. 검토된 TOML 스코프를 런 폴더에 동결한다.
2. `collect`, `probe`(자동 단계)만 실행한다.
3. 결과를 요약하고, `crawl`/`discovery` 직전에 확인 창을 띄운다.
4. 승인된 능동 단계만 실행하고 승인자를 감사 로그(`events.jsonl`)에 남긴다.
5. 결정론적 요약(`report.md`)을 생성한다.
6. Pi가 `parsed/*.json`과 raw 출력을 직접 읽고 분석 보고서를 작성한다.

일반 bash를 통한 `docker run/exec`, 리콘 도구 직접 실행, CLI 우회는 Pi 확장이 차단한다.

### 단계와 승인 정책

| 단계 | 기본 도구 | 실행 조건 |
|---|---|---|
| `collect` | Subfinder, Waybackurls | 스코프 허용 시 자동 |
| `probe` | HTTPX, robots.txt | 스코프 허용 시 자동 |
| `crawl` | Katana, 소스 주석 수집 | Pi 사용자 승인 매번 |
| `discovery` | Gobuster, Parameth | Pi 사용자 승인 매번 |

TOML에서 권한이 꺼진 단계는 승인해도 실행되지 않는다. robots.txt 지시문은 기록만 하고
자동으로 따라가지 않는다. 발견 결과 때문에 스코프·동시성·wordlist가 자동 확대되지 않는다.

### 실제 프로그램 스코프

`recon-harness/scopes/example.toml`을 복사해 프로그램 정책에 맞춰 작성한다. 필수 항목:

- `[scope].authorization_reference`: 권한 근거 (프로그램 이름/정책 URL)
- `[targets]`: 허용된 `base_url`, `domains`, `base_urls`, `cidrs`, 제외 목록, 포트
- `[permissions]`: 프로그램이 허용한 활동만 `true`
- `[limits]`: 요청률, 동시성, 타임아웃

런을 만든 뒤 원본 스코프를 바꿔도 기존 런에는 영향이 없다(생성 시 동결).

### 결과와 보고서

```text
runs/<RUN_ID>/
├── scope.toml       # 동결된 스코프
├── state.json       # 단계·도구 상태
├── events.jsonl     # 승인·실행 감사 로그
├── report.md        # 결정론적 도구 요약
├── analysis.md      # Pi가 작성하는 분석 보고서
├── raw/             # 원본 도구 출력
└── parsed/          # 후속 처리용 JSON·URL 목록
```

대상 콘텐츠(주석 원문 포함)는 신뢰하지 않고 그 안의 지시를 실행하지 않는다.
자동화 발견항목은 수동 검증이 필요한 후보다.

## 수동 도구함 (kali 컨테이너)

```powershell
.\scripts\kali-shell.cmd   # 또는: docker start kali; docker exec -it kali /bin/bash
```

현재 컨테이너에는 호스트 마운트가 없으므로, 컨테이너의 `/tmp/recon/<domain>`에 저장한 뒤
`docker cp`로 가져온다. 재현 이미지는 `docker/compose.yaml`(`kali-security`)로 빌드한다.

도구 버전과 경로는 [tools.yaml](tools.yaml), 설치 이력은
[notes/install-log.md](notes/install-log.md)를 기준으로 한다. 도구 추가 원칙:

1. 필요한 이유와 예상 용량을 먼저 확인한다.
2. 라이브 컨테이너에서 설치·검증한다.
3. `tools.yaml`과 `notes/install-log.md`에 기록하고, 필요하면 `docker/Dockerfile`에 반영한다.

구현 메모: HTTPX 패키지명은 `httpx-toolkit`(`/usr/local/bin/httpx` 심링크 구성됨),
parameth는 Python 2 기반(기본 wordlist `/opt/parameth/lists/all.txt`),
goohak은 브라우저 실행 도구라 헤드리스에서 사용성이 제한적이다.

Nuclei와 Metasploit은 재현용 Kali 이미지에서도 제외한다. 이후 각각 별도의 검증 및
침투 테스트 이미지로 분리한다. Nmap은 Pi 에이전트 경로에서는 사용하거나 대체 실행하지 않는다.

## Google Dork 생성기

Google에 자동 요청하지 않고 검색식만 만든다.

```powershell
cd C:\Users\ytyt\Desktop\security\kail
py -3 .\tool-scripts\dorkgen.py example.com --urls --output .\results\example.com\dorks.txt
```

## 문제 해결

```powershell
cd C:\Users\ytyt\Desktop\security\kail\recon-harness
py -3 -m recon_harness.cli doctor --scope scopes\example.toml
py -3 -m unittest discover -s tests -v
py -3 -m compileall -q recon_harness
```

`doctor`에서 이미지가 없으면 `docker compose -f docker\compose.recon-web.yaml build`를 다시
실행한다. 로컬 랩 네트워크가 없으면 `.\scripts\start-lab.ps1`을 먼저 실행한다.
리콘 중 요청량이 예상보다 많거나 스코프가 불확실하면 즉시 취소하고 프로그램 정책부터 다시 확인한다.

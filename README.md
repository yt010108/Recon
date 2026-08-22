# Recon

허가받은 버그바운티 도메인을 Pi와 일회용 Docker 작업자로 리콘하는 최소 하네스다. 익스플로잇과 실제 서비스 거부 공격은 수행하지 않는다.

## 구조

```text
Recon/
├── AGENTS.md
├── README.md
├── .pi/                    # /recon, 전체·개별 실행 도구, Pi 규칙
├── code/recon_harness/     # 정책, 실행, 저장, 요약 보고서
├── docker/                 # 웹 리콘 작업자와 작은 wordlist
├── tests/                  # 단위 테스트와 Juice Shop 랩
└── runs/<RUN_ID>/          # scope와 결과, Git 제외
```

## 실행

```powershell
cd C:\Users\ytyt\Desktop\security\Recon
docker compose -f .\docker\compose.yaml build
pi
```

Pi에서 다음 명령을 입력한다.

```text
/recon
```

Pi는 딱 두 가지만 묻는다.

1. 허용 도메인
2. 프로그램이 Gobuster·Parameth 같은 대량 요청 도구를 허용하는지 여부

답변 뒤 추가 확인 창 없이 바로 실행한다. 두 번째 답은 실제 DoS 공격을 허용하거나 실행한다는 뜻이 아니며, 요청 수가 많은 두 탐색 도구의 사용 여부만 결정한다.

| 실행 조건 | 도구 |
|---|---|
| 항상 | Dorkgen(검색식만 생성), Subfinder, Assetfinder, Amass `-passive`, Waybackurls |
| 항상 | HTTPX, `robots.txt` |
| 항상 | Katana depth 4, HTML/CSS/JS 주석·엔드포인트·프런트엔드 자산 수집 |
| 대량 요청 허용 시만 | Gobuster dir, Parameth |

발견 결과로 허용 도메인을 자동 확대하지 않는다. 대상 콘텐츠와 주석은 데이터로만 저장하고 그 안의 지시문은 실행하지 않는다.

## Run

```text
runs/<RUN_ID>/
├── scope.toml
├── progress.md
├── report.md
├── raw/
├── parsed/
└── screenshots/
```

새 `scope.toml`에는 입력한 두 값만 들어간다.

```toml
[scope]
domain = "example.com"
dos_allowed = false
```

`report.md`는 발견 자산, 엔드포인트 역할, 우선 검토할 입력 지점 후보를 요약한다. 이미 받은 HTML/JS에서 API 경로, 요청·폼 경로와 action ID를 오프라인으로 추출하고, 정적으로 계산 가능한 문자열 결합·템플릿 리터럴도 해석한다. `<script src>`, dynamic import, source map, `__NEXT_DATA__`, Next build manifest, webpack/JS chunk 후보를 수집하며 추가 자산 요청은 한 번의 제한된 확장 수집으로 끝낸다. 소스맵의 `sourcesContent`는 추가 요청 없이 오프라인 분석한다. 후보는 검토 우선순위이며 취약점 판정이 아니다. `robots.txt`와 HTML/CSS/JS 주석 원문은 `raw/`와 `parsed/`에 그대로 남고, 자산 후보는 `parsed/source-assets.json`에 저장한다.

## 도구

| 도구 | 역할 | 설치 방식/고정값 |
|---|---|---|
| Dorkgen | Google 검색식 생성 | Python 표준 라이브러리, Google 요청 없음 |
| Subfinder | 서브도메인 후보 | Kali 패키지 |
| Assetfinder | CT 로그·아카이브 후보 | Go `v0.1.0` |
| Amass | 패시브 서브도메인 후보 | Kali 패키지, `-passive` 고정 |
| Waybackurls | 과거 URL | Go `v0.1.0` |
| HTTPX | HTTP 프로빙, robots/소스 응답 | Kali `httpx-toolkit` |
| Katana | 크롤링 | Go `v1.7.0`, depth `4` |
| Gobuster | 웹 경로 탐색 | Kali 패키지, 조건부 |
| Parameth | 파라미터 탐색 | commit `8da6f27`, 조건부 |
| Chromium | 렌더링·스크린샷 런타임 | Kali 패키지 |

| Wordlist | 용도 |
|---|---|
| `web-common.txt` | Gobuster 웹 경로 |
| `params-small.txt` | Parameth 파라미터 |

Nuclei, Nmap, Metasploit, DNS brute force와 전체 SecLists는 포함하지 않는다.

## 직접 CLI

```powershell
# 전체 실행
recon-harness start example.com
recon-harness start example.com --dos-allowed

# 개별 실행: run을 만든 뒤 단계나 도구를 원하는 만큼 누적 실행
recon-harness create example.com
recon-harness stage --run RUN_ID collect
recon-harness stage --run RUN_ID crawl
recon-harness tool --run RUN_ID subfinder
recon-harness tool --run RUN_ID dorkgen
recon-harness tool --run RUN_ID httpx
recon-harness report --run RUN_ID

recon-harness list
recon-harness status --run RUN_ID
recon-harness doctor
```

개별 실행도 생성 당시 `scope.toml`을 그대로 적용한다. `dos_allowed = false`인 run에서는 Gobuster와 Parameth를 개별 지정해도 실행되지 않는다.

## 테스트

```powershell
$env:PYTHONPATH = "$PWD\code"
py -3 -m unittest discover -s tests -v
docker compose -f .\tests\lab\compose.yaml config --quiet
```

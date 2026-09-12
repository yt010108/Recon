# Recon Tool Usage

각 도구는 기존 run을 만든 뒤 `recon-harness tool --run RUN_ID <tool>` 형태로 개별 실행할 수 있다.
전체 리콘은 `recon-harness start example.com`, run만 먼저 만들려면 `recon-harness create example.com`을 사용한다.

## dorkgen

Google에 직접 요청하지 않고 대상 도메인용 검색식을 로컬에서 생성한다.

```powershell
recon-harness tool --run RUN_ID dorkgen
```

결과: `collect/google-dorks.txt`

## subfinder

대상 도메인의 서브도메인을 passive 방식으로 수집하고 `domains.txt`에 병합한다.

```powershell
recon-harness tool --run RUN_ID subfinder
```

결과: `collect/domains.txt`

## assetfinder

Assetfinder로 서브도메인을 수집한다. 기존 collect 결과와 중복 제거 후 병합된다.

```powershell
recon-harness tool --run RUN_ID assetfinder
```

결과: `collect/domains.txt`

## amass_enum

Amass의 passive enum만 사용해 서브도메인을 수집한다.

```powershell
recon-harness tool --run RUN_ID amass_enum
```

결과: `collect/domains.txt`

## waybackurls

Wayback 계열 데이터에서 과거 URL을 수집하고 현재 scope 안의 URL만 보존한다.

```powershell
recon-harness tool --run RUN_ID waybackurls
```

결과: `collect/wayback-urls.txt`

## httpx

수집한 도메인과 시작 URL에 HTTP probe를 수행해 살아있는 URL을 확인한다.

```powershell
recon-harness tool --run RUN_ID httpx
```

결과: `probe/alive-urls.txt`, `probe/httpx.json`

## robots_txt

살아있는 origin의 `/robots.txt`를 가져와 directive, comment, sitemap 정보를 정리한다.
내부적으로 HTTPX를 사용한다.

```powershell
recon-harness tool --run RUN_ID robots_txt
```

결과: `probe/robots.json`

## nuclei

살아있는 URL을 대상으로 Nuclei 템플릿을 실행한다. 전체 `start`에는 자동 포함되지 않아 필요할 때 별도 실행한다.

```powershell
recon-harness tool --run RUN_ID nuclei
```

결과: `probe/raw/nuclei.jsonl`, `probe/nuclei-findings.json`

## katana

살아있는 URL을 seed로 깊이 2까지 크롤링하고 scope 내부 URL만 저장한다.

```powershell
recon-harness tool --run RUN_ID katana
```

결과: `crawl/katana-urls.txt`

## source_comments

수집된 HTML/CSS/JS 소스를 확인해 주석과 API/endpoint/action 후보를 추출한다.
내부적으로 HTTPX를 사용한다.

```powershell
recon-harness tool --run RUN_ID source_comments
```

결과: `crawl/source-comments.json`, `crawl/source-endpoints.json`

## url_discovery

Wayback, robots.txt, Katana, source 결과를 하나의 URL queue로 합치고 새 in-scope URL을 재확인한다.
내부 discovery 단계에서 사용하지만 CLI로도 실행할 수 있다.

```powershell
recon-harness tool --run RUN_ID url_discovery
```

결과: `discovery/url-queue.jsonl`

## gobuster_dir

기본 wordlist로 시작 URL의 디렉터리/경로를 탐색한다. SPA wildcard가 감지되면 동일 길이를 제외하고 재시도한다.

```powershell
recon-harness tool --run RUN_ID gobuster_dir
```

결과: `discovery/gobuster-dir.json`

전체 실행에서 자동 사용하려면 처음부터 `--gobuster` 옵션을 준다.

```powershell
recon-harness start example.com --gobuster
```

## parameth

선택한 URL 하나를 대상으로 파라미터 후보를 찾는다. 반드시 `--target-url`을 지정해야 한다.

```powershell
recon-harness tool --run RUN_ID parameth --target-url https://example.com/search
```

결과: `discovery/parameth.json`

## surface

수집 결과를 기능 단위 route로 정규화하고 중요 후보와 coverage를 만든다. 네트워크 요청 없이 로컬에서 처리한다.

```powershell
recon-harness tool --run RUN_ID surface
```

결과: `normalize/routes.jsonl`, `normalize/candidates.json`, `normalize/coverage.json`

## 자주 쓰는 명령

```powershell
# 전체 실행
recon-harness start example.com

# 특정 단계만 실행
recon-harness stage --run RUN_ID collect
recon-harness stage --run RUN_ID probe
recon-harness stage --run RUN_ID crawl
recon-harness stage --run RUN_ID discovery
recon-harness stage --run RUN_ID normalize

# 상태 / 보고서
recon-harness status --run RUN_ID
recon-harness report --run RUN_ID

# Docker 및 도구 설치 확인
recon-harness doctor
```

허가받은 대상과 설정된 scope 안에서만 실행한다.

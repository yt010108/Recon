# Recon

허가받은 웹 대상을 Pi와 Docker 작업자로 리콘하는 하네스다.

두 모드를 지원한다.

- `internet`: 기존 도메인 기반 OSINT/웹 리콘
- `competition`: 대회에서 명시적으로 허용된 내부 IPv4/CIDR 기반 웹 리콘

## 시작

```powershell
cd C:\Users\ytyt\Desktop\security\Recon
docker compose -f .\docker\compose.yaml build
pi
```

Pi에서 `/recon`은 기존 인터넷 도메인 모드를, `/recon-competition`은 내부망 대회 모드를 사용한다.

## Internet 모드

전체 실행에는 다음 네 단계가 들어간다.

| 단계 | 도구 |
|---|---|
| collect | Dorkgen, Subfinder, Assetfinder, Amass passive, Waybackurls |
| probe | HTTPX, `robots.txt` |
| crawl | Katana, HTML/CSS/JS 주석·엔드포인트·manifest·sourcemap 수집 |
| discovery | Gobuster dir, Parameth |

```powershell
recon-harness start example.com
```

## Competition 모드

인터넷 검색/과거 URL/패시브 서브도메인 수집을 하지 않는다. 입력한 IPv4 주소 또는 CIDR과 허용 포트만 대상으로 한다. 한 run의 IPv4 범위는 최대 4096개 주소로 제한한다.

| 단계 | 도구 |
|---|---|
| collect | Nmap TCP connect + light service/version detection (`network_discovery`) |
| probe | HTTPX status/title/web server/technology fingerprint, `robots.txt` |
| crawl | Katana, HTML/CSS/JS 주석·API·manifest·sourcemap 수집 |
| discovery | 각 활성 웹 origin에 Gobuster dir, Parameth |

`network_discovery`는 `-sV --version-light`로 허용 포트의 서비스 이름, product, version, extra info, CPE와 Nmap detection confidence를 기록한다. HTTPX 결과는 같은 `host:port`에 합쳐 web server, title, HTTP status, detected technologies를 `service-inventory.json`에 보강한다.

기본 포트는 흔한 웹 서비스 포트 집합이다. 대회가 별도 포트를 지정하면 `--ports`로 명시한다.

```powershell
# /24 내부망 + 기본 웹 포트
recon-harness competition-start 10.10.10.0/24

# 여러 대상 + 명시 포트
recon-harness competition-start 10.10.10.10 10.10.10.20 --ports 80,443,8080,8443

# 네트워크 요청 없이 run만 생성
recon-harness competition-create 10.10.10.0/24 --ports 80,443,8080
```

Competition scope 예시:

```toml
[scope]
mode = "competition"
targets = ["10.10.10.0/24"]
ports = [80, 443, 8080, 8443]
```

Nmap 결과에서 찾은 IP가 입력 CIDR 밖이면 후속 처리하지 않고, 모든 HTTP(S) URL도 요청 직전에 같은 IP/포트 경계를 다시 검사한다. Katana는 HTTPX가 확인한 origin만 scope regex에 넣는다.

## Nuclei

Nuclei는 전체 리콘에서 제외한다. 필요할 때 기존 run에 단독 실행하며 결과는 같은 `report.md`와 `parsed/attack-surface.json`에 포함된다.

별도 `Dockerfile.nuclei` 이미지에서 Nuclei `v3.11.1`과 템플릿 `v10.4.7`을 사용한다.

```powershell
recon-harness tool --run RUN_ID nuclei
```

## 결과

```text
runs/<RUN_ID>/
├── scope.toml
├── progress.md
├── report.md
├── raw/
├── parsed/
│   └── attack-surface.json
└── screenshots/
```

`report.md`의 `우선 검토할 입력 지점`에는 URL/파라미터뿐 아니라 가능한 경우 발견한 소스 URL과 line 또는 도구 artifact 위치를 함께 표시한다.

`parsed/attack-surface.json`은 후속 agent가 읽기 위한 통합 결과다. scope, 네트워크 서비스, HTTPX 웹 서비스, URL별 role/sink hint/parameter, 발견 provenance, source endpoint/action, Parameth 결과, Nuclei 후보를 포함한다. HTML form과 정적으로 해석 가능한 fetch/Axios 호출은 `methods`, `query_parameters`, `body_parameters`, `form_fields`, `content_types`로 정규화하며, 각 endpoint에는 근거 기반 `confidence`와 `confidence_reasons`를 기록한다.

sink/role 분류는 경로와 파라미터의 토큰을 정확히 비교한다. 예를 들어 `id`는 `userId`의 camel-case 토큰과는 일치하지만 `/valid`의 부분 문자열은 입력 지점으로 오인하지 않는다.

`parsed/findings.json`은 수동 검증 큐다. 입력이 있거나 상태 변경 메서드를 사용하는 후보를 안정적인 `finding_id`로 관리하고 최초 상태를 `unverified`로 둔다. 보고서를 다시 생성해도 같은 ID의 `status`, `notes`, 요청/응답 artifact와 사용자가 추가한 필드는 보존된다.

Competition 모드에서는 추가로 다음 파일을 만든다.

```text
parsed/hosts.txt
parsed/network-services.json
parsed/service-inventory.json
parsed/alive-urls.txt
parsed/httpx.json
parsed/web-fingerprints.json
parsed/katana-urls.txt
parsed/source-endpoints.json
parsed/gobuster-dir.json
parsed/parameth.json
parsed/attack-surface.json
parsed/findings.json
```

`service-inventory.json`은 비웹 서비스를 포함한 포트별 통합 inventory다. 가능한 경우 `service_name`, `product`, `version`, `extra_info`, `cpes`, `confidence`, `web_server`, `technologies`, `title`, `http_status`, `web_url`을 포함한다. `web-fingerprints.json`은 HTTPX가 실제 웹으로 확인한 origin만 간단히 정규화한 파일이다.

Competition 모드의 Parameth는 origin만 검사하지 않고, 소스에서 찾은 endpoint와 정적 파일을 제외한 Katana URL을 우선 대상으로 사용한다. 실행 폭주를 막기 위해 한 run에서 최대 60개 endpoint를 검사하며, 정규화한 파라미터 이름을 attack surface와 findings queue에 합친다.

검증 상태 권장 흐름은 `unverified` → `testing` → `confirmed` 또는 `false_positive`다. `findings.json`의 후보는 취약점 확정 결과가 아니므로 실제 제출 전 요청/응답 artifact와 영향도를 수동으로 확인한다.

## CLI

```powershell
# 인터넷 전체 실행
recon-harness start example.com

# 대회 전체 실행
recon-harness competition-start 10.10.10.0/24 --ports 80,443,8080

# 개별 실행
recon-harness create example.com
recon-harness competition-create 10.10.10.0/24
recon-harness stage --run RUN_ID crawl
recon-harness tool --run RUN_ID httpx
recon-harness tool --run RUN_ID network_discovery
recon-harness tool --run RUN_ID nuclei
recon-harness report --run RUN_ID

recon-harness list
recon-harness status --run RUN_ID
recon-harness doctor
```

## 테스트

```powershell
$env:PYTHONPATH = "$PWD\code"
py -3 -m unittest discover -s tests -v
docker compose -f .\docker\compose.yaml config --quiet
```

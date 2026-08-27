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
| collect | Nmap TCP connect scan (`network_discovery`) |
| probe | HTTPX, `robots.txt` |
| crawl | Katana, HTML/CSS/JS 주석·API·manifest·sourcemap 수집 |
| discovery | 각 활성 웹 origin에 Gobuster dir, Parameth |

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

`parsed/attack-surface.json`은 후속 agent가 읽기 위한 통합 결과다. scope, 네트워크 서비스, HTTPX 웹 서비스, URL별 role/sink hint/parameter, 발견 provenance, source endpoint/action, Parameth 결과, Nuclei 후보를 포함한다.

Competition 모드에서는 추가로 다음 파일을 만든다.

```text
parsed/hosts.txt
parsed/network-services.json
parsed/alive-urls.txt
parsed/httpx.json
parsed/katana-urls.txt
parsed/source-endpoints.json
parsed/gobuster-dir.json
parsed/parameth.json
parsed/attack-surface.json
```

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

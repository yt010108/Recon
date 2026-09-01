# Recon

허가받은 URL, 도메인 또는 IP를 Pi와 Docker 작업자로 리콘하는 하네스다. 수집 결과는 모두 보존하고, 첫 보고서는 기능 단위 route와 상위 후보 20개로 정리한다.

## 시작

```powershell
cd C:\Users\ytyt\Desktop\security\Recon
docker compose -f .\docker\compose.yaml build
pi
```

Pi에서 `/recon`을 입력하면 허용 대상을 묻고 바로 실행한다. Pi extension은 `bash`, `docker run/exec`, 개별 리콘 바이너리의 직접 실행을 차단하지 않는다.

전체 실행에는 다음 단계가 들어간다.

| 단계 | 도구 |
|---|---|
| collect | Dorkgen, Subfinder, Assetfinder, Amass passive, Waybackurls |
| probe | HTTPX, `robots.txt` |
| crawl | Katana, HTML/CSS/JS 주석·엔드포인트 수집 |
| discovery | 출처 통합 URL 큐·최대 2회 재확인, 선택형 Gobuster dir, Parameth 후보 생성 |
| normalize | 값만 다른 URL을 기능 route로 합치고 상위 검토 후보 20개 선정 |

Nuclei는 전체 리콘에서 제외했다. 필요할 때 기존 run에 단독 실행하며 결과는 같은 `report.md`에 포함된다. 별도 [Dockerfile.nuclei](docker/Dockerfile.nuclei) 이미지에서 Nuclei `v3.11.1`과 템플릿 `v10.4.7`을 사용하고, 하네스가 템플릿 종류·태그·리다이렉트·Interactsh·속도·동시성을 제한하지 않는다.

Docker 실행에도 non-root 강제, read-only rootfs, capability drop, CPU·메모리·PID 제한을 추가하지 않는다. 각 명령이 끝나면 컨테이너만 삭제한다.

## 결과

```text
runs/<RUN_ID>/
├── scope.toml
├── progress.md
├── report.md
├── collect/
│   ├── raw/
│   ├── report.md
│   ├── domains.txt
│   └── wayback-urls.txt
├── probe/
│   ├── raw/
│   ├── report.md
│   ├── alive-urls.txt
│   └── httpx.json
├── crawl/
│   ├── raw/
│   ├── report.md
│   └── katana-urls.txt
├── discovery/
│   ├── raw/
│   ├── report.md
│   └── url-queue.jsonl
├── normalize/
│   ├── raw/
│   ├── report.md
│   ├── routes.jsonl
│   ├── candidates.json
│   └── coverage.json
└── screenshots/
```

Wayback·robots.txt·Katana·source 결과는 출처를 보존한 `discovery/url-queue.jsonl`로 합친다.
새 in-scope URL만 HTTPX로 확인하고, 새 live origin과 HTML 후보만 Katana에 최대 2회
다시 넣는다. 실패한 명령은 같은 round에서 재시도하며, 새 항목이 없으면 즉시 끝낸다.
큐는 전체 1,000개·origin별 100개, Katana seed는 run 전체에서 origin별 3개로 제한하고
재확인 Katana는 동시 요청 1개·초당 5개로 실행한다.

각 단계가 끝나면 `<단계>/report.md`를 갱신한다. `discovery/report.md`는 URL Discovery와
실행된 Gobuster·Parameth 결과를 하나의 경로 트리로 합친다. Gobuster는 선택 실행한다.
Parameth는 자동 실행하지 않고 `discovery/parameth-targets.txt`에서 사용자가 URL을
선택했을 때만 해당 URL에 실행한다.
루트 `report.md`는 Normalize 완료 후 만드는 최종 보고서다.

`report.md`는 중요 route 최대 50개를 Method·파라미터·중요도만 포함한 사이트맵으로
보여준다. 별도로 중요 엔드포인트 최대 20개, 보안 관련 주석 최대 10개,
source map·manifest·동적 chunk 등 중요 소스 자산 최대 10개만 보여준다.
민감한 값은 보고서에서 가리고 원본 JSON에는 수집 결과를 그대로 보존한다.

`scope.toml`은 허용 도메인/IP와 시작 URL을 저장한다.

```toml
[scope]
domain = "example.com"
base_url = "https://example.com"
domain_timeout = 180
run_gobuster = false
```

Nuclei 원본 JSONL은 `probe/raw/nuclei.jsonl`, 정리 결과는 `probe/nuclei-findings.json`에 저장되고 `report.md`에 합쳐진다.

## CLI

```powershell
# 전체 실행
recon-harness start example.com
recon-harness start https://example.com/app
recon-harness start 10.20.30.5
recon-harness start example.com --domain-timeout 120
recon-harness start example.com --gobuster

# 개별 실행
recon-harness create example.com
recon-harness stage --run RUN_ID crawl
recon-harness tool --run RUN_ID httpx
recon-harness tool --run RUN_ID url_discovery
recon-harness tool --run RUN_ID parameth --target-url https://example.com/search
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

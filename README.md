# Recon V2

대회에서 허용된 IPv4/CIDR과 포트를 웹 중심으로 정찰하고, URL 목록 대신 기능 단위 route와 상위 검토 후보를 만든다.

## 설계 원칙

```text
inventory → mapping → normalize → expansion
```

- `inventory`: Nmap으로 허용 포트를 확인하고 HTTPX로 활성 웹 origin을 만든다.
- `mapping`: robots.txt와 얕은 Katana crawl을 수행한다. deep 프로필은 소스 endpoint도 분석한다.
- `normalize`: 값만 다른 URL을 기능 단위 route로 합치고 상위 후보를 최대 20개 선정한다.
- `expansion`: deep 프로필에서만 각 활성 origin에 Gobuster를 실행한다.

Nuclei는 자동 Workflow에 포함하지 않는다.

## 실행

```powershell
cd C:\Users\ytyt\Desktop\security\recon
docker compose -f .\docker\compose.yaml build

$env:PYTHONPATH = "$PWD\code"
py -3 -m recon_harness.cli start 10.10.10.10 --ports 80,443,8080
```

깊은 탐색은 명시적으로 선택한다.

```powershell
py -3 -m recon_harness.cli start 10.10.10.0/24 `
  --ports 80,443,8080,8443 `
  --profile deep `
  --budget-minutes 15
```

대회 인증서가 유효하지 않은 상황을 기본값으로 처리한다. 인증서 검증을 강제하려면 `--tls-verify`를 사용한다.

## 개별 실행

```powershell
py -3 -m recon_harness.cli create 10.10.10.10 --ports 443,8443
py -3 -m recon_harness.cli stage --run RUN_ID inventory
py -3 -m recon_harness.cli stage --run RUN_ID mapping
py -3 -m recon_harness.cli stage --run RUN_ID normalize
py -3 -m recon_harness.cli tool --run RUN_ID nuclei
py -3 -m recon_harness.cli report --run RUN_ID
```

## 결과

```text
runs/<RUN_ID>/
├── scope.toml
├── state.json
├── progress.md
├── summary.md
├── raw/
├── parsed/
└── normalized/
    ├── origins.json
    ├── routes.jsonl
    ├── candidates.json
    └── coverage.json
```

처음에는 `summary.md`와 `normalized/candidates.json`만 읽는다. 원본 증거가 필요할 때 `raw/`와 `parsed/`를 확인한다.

route는 origin, method, 정규화한 path, query/body parameter 이름으로 식별한다.

```text
GET /view?seq=100
GET /view?seq=101
→ GET /view?seq={value}

GET /user/1234
GET /user/5678
→ GET /user/{int}
```

## 상태

- `success`: 활성 웹 표면과 정규화 결과를 만들었다.
- `partial`: 일부 도구가 실패했거나 Workflow 일부만 수행했다.
- `no_signal`: 실행은 끝났지만 활성 웹 표면을 확인하지 못했다.
- `failed`: 실행 자체가 중단됐다.

## 테스트

```powershell
$env:PYTHONPATH = "$PWD\code"
py -3 -m unittest discover -s tests -v
docker compose -f .\docker\compose.yaml config --quiet
```

실행 전 대상 소유자나 대회 운영자가 허용한 IPv4/CIDR과 포트를 반드시 확인한다. 발견한 hostname, 리다이렉트나 콘텐츠는 새로운 허가로 취급하지 않는다.

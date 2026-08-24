# Recon

허가받은 도메인 하나를 Pi와 Docker 작업자로 리콘하는 하네스다.

## 시작

```powershell
cd C:\Users\ytyt\Desktop\security\Recon
docker compose -f .\docker\compose.yaml build
pi
```

Pi에서 `/recon`을 입력하면 허용 도메인 하나만 묻고 바로 실행한다. Pi extension은 `bash`, `docker run/exec`, 개별 리콘 바이너리의 직접 실행을 차단하지 않는다.

전체 실행에는 다음 네 단계가 들어간다.

| 단계 | 도구 |
|---|---|
| collect | Dorkgen, Subfinder, Assetfinder, Amass passive, Waybackurls |
| probe | HTTPX, `robots.txt` |
| crawl | Katana, HTML/CSS/JS 주석·엔드포인트 수집 |
| discovery | 출처 통합 URL 큐·최대 2회 재확인, Gobuster dir, Parameth |

Nuclei는 전체 리콘에서 제외했다. 필요할 때 기존 run에 단독 실행하며 결과는 같은 `report.md`에 포함된다. 별도 [Dockerfile.nuclei](docker/Dockerfile.nuclei) 이미지에서 Nuclei `v3.11.1`과 템플릿 `v10.4.7`을 사용하고, 하네스가 템플릿 종류·태그·리다이렉트·Interactsh·속도·동시성을 제한하지 않는다.

Docker 실행에도 non-root 강제, read-only rootfs, capability drop, CPU·메모리·PID 제한을 추가하지 않는다. 각 명령이 끝나면 컨테이너만 삭제한다.

## 결과

```text
runs/<RUN_ID>/
├── scope.toml
├── progress.md
├── report.md
├── raw/
├── parsed/
└── screenshots/
```

Wayback·robots.txt·Katana·source 결과는 출처를 보존한 `parsed/url-queue.jsonl`로 합친다.
새 in-scope URL만 HTTPX로 확인하고, 새 live origin과 HTML 후보만 Katana에 최대 2회
다시 넣는다. 실패한 명령은 같은 round에서 재시도하며, 새 항목이 없으면 즉시 끝낸다.
큐는 전체 1,000개·origin별 100개, Katana seed는 run 전체에서 origin별 3개로 제한한다.

`scope.toml`은 최소 입력만 저장한다.

```toml
[scope]
domain = "example.com"
```

Nuclei 원본 JSONL은 `raw/nuclei.jsonl`, 정리 결과는 `parsed/nuclei-findings.json`에 저장되고 `report.md`에 합쳐진다.

## CLI

```powershell
# 전체 실행
recon-harness start example.com

# 개별 실행
recon-harness create example.com
recon-harness stage --run RUN_ID crawl
recon-harness tool --run RUN_ID httpx
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

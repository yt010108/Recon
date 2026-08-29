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

## Playwright

Node.js용 Playwright와 Chromium이 로컬에 설치되어 있다. JS 렌더링, SPA 라우팅, 폼 입력 등 브라우저 상호작용이 필요한 확인에 사용할 수 있다.

```bash
npm install
npx playwright install chromium
npx playwright --version
```

Node.js 스크립트에서는 다음처럼 사용한다.

```js
const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto("http://ALLOWED-TARGET/", { waitUntil: "networkidle" });
  console.log(await page.title());
  await browser.close();
})();
```

### Python Playwright

Python 3.11이 설치되어 있으며, 프로젝트 전용 `.venv`에 Python Playwright와 Chromium을 설치한다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe -c "from playwright.sync_api import sync_playwright; print('Python Playwright OK')"
```

Python 스크립트 예시:

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("http://ALLOWED-TARGET/", wait_until="networkidle")
    print(page.title())
    browser.close()
```

대회 모드에서는 대회에서 명시적으로 허용된 IP/CIDR와 포트 범위 안에서만 사용한다.

### Competition 별도 실행

`competition-start`의 네 단계에는 Playwright가 자동 포함되지 않는다. 대회에서 브라우저 자동화와 AI 사용이 허용된 경우에도 Playwright는 별도 실행하며, 명시된 IPv4와 포트만 `TARGET_URL`로 지정한다. 발견된 링크나 리다이렉트로 범위를 확대하지 않는다.

다음 예시는 대상 origin을 브라우저로 열고, 같은 IP/포트의 요청·응답만 기록하며, 외부 origin 요청은 차단한다. 비밀번호 변경, 계정 생성, 구매 등 상태 변경 동작은 포함하지 않는다.

```bash
RUN_DIR="runs/<RUN_ID>" \
TARGET_URL="http://<ALLOWED_IPV4>:<ALLOWED_PORT>" \
node - <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const { chromium } = require("playwright");

const target = new URL(process.env.TARGET_URL);
if (!["http:", "https:"].includes(target.protocol) || !net.isIPv4(target.hostname)) {
  throw new Error("TARGET_URL must use an allowed IPv4 address");
}
if (!target.port) throw new Error("TARGET_URL must include an explicit port");
const targetPort = Number(target.port);
const inScope = (value) => {
  const url = new URL(value);
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  return url.hostname === target.hostname && port === targetPort;
};

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const requests = [];
  const responses = [];

  await page.route("**/*", async (route) => {
    try {
      if (!inScope(route.request().url())) return route.abort();
      await route.continue();
    } catch {
      await route.abort();
    }
  });
  page.on("request", (request) => {
    if (inScope(request.url())) requests.push({ method: request.method(), url: request.url() });
  });
  page.on("response", (response) => {
    if (inScope(response.url())) responses.push({ status: response.status(), url: response.url() });
  });

  const navigation = await page.goto(target.href, {
    waitUntil: "domcontentloaded",
    timeout: 30000,
  });
  const result = {
    target: target.href,
    status: navigation?.status() ?? null,
    final_url: page.url(),
    title: await page.title(),
    request_count: requests.length,
    response_count: responses.length,
    requests,
    responses,
  };

  const runDir = path.resolve(process.env.RUN_DIR || ".");
  fs.mkdirSync(path.join(runDir, "parsed"), { recursive: true });
  fs.mkdirSync(path.join(runDir, "screenshots"), { recursive: true });
  fs.writeFileSync(
    path.join(runDir, "parsed", "playwright-manual.json"),
    JSON.stringify(result, null, 2) + "\n",
  );
  await page.screenshot({ path: path.join(runDir, "screenshots", "playwright-root.png"), fullPage: true });
  console.log(JSON.stringify({ target: result.target, status: result.status, title: result.title }));
  await context.close();
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
NODE
```

`RUN_DIR`에는 기존 run 디렉터리를 넣고, 대상이 호스트에서 도달되지 않는 내부망이면 Playwright 실행 환경을 해당 Docker 네트워크에 연결해야 한다. 생성 결과는 `parsed/playwright-manual.json`과 `screenshots/playwright-root.png`에 저장된다. 이 단계는 수동 검증용이며 자동 결과만으로 취약점을 확정하지 않는다.

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
parsed/source-hidden.json
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

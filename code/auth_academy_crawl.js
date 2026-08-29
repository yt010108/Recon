const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ORIGIN = 'https://academy.kisa.or.kr';
const RUN_DIR = 'runs/20260829-011528-academy.kisa.or.kr-706647';
const OUT_DIR = path.join(RUN_DIR, 'raw', 'manual-auth');
const MAX_URLS = 120;
const MAX_DEPTH = 3;
const USER_AGENT = 'authorized-recon-readonly/1.0';

const blockedPath = /(?:logout|logOut|insert|update|delete|remove|cancel|withdraw|drop|submit|save|payment|\bpay\b|write|register|join|check|confirm|finish|issue|download|fileDown|upload|applyStep|applyForm|applyAction|action[A-Z]|process|proc\.|test|exam|quiz|survey)/i;
const safePathHint = /(?:list|detail|view|select|current|history|status|info|guide|plan|intro|index|main|privacy|notice|faq|class|mypage|education|lecture|course|bbs)/i;
const staticExt = /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|hwp|zip|xlsx?|docx?|pptx?|mp4|mp3)(?:$|\?)/i;
const sensitiveKey = /(?:user|member|login|email|phone|mobile|birth|name|token|session|auth|password|passwd|pwd|key)/i;

function normalize(raw, base) {
  try {
    const u = new URL(raw, base);
    if (u.origin !== ORIGIN) return null;
    u.hash = '';
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    return u.href;
  } catch {
    return null;
  }
}

function redact(raw) {
  try {
    const u = new URL(raw);
    for (const [key] of [...u.searchParams]) {
      if (sensitiveKey.test(key)) u.searchParams.set(key, '<redacted>');
    }
    return u.href;
  } catch {
    return raw;
  }
}

function safeToFetch(raw) {
  try {
    const u = new URL(raw);
    if (u.origin !== ORIGIN || staticExt.test(u.pathname)) return false;
    if (blockedPath.test(u.pathname)) return false;
    if (u.searchParams.size > 6) return false;
    for (const [key] of u.searchParams) if (sensitiveKey.test(key)) return false;
    return u.pathname === '/' || safePathHint.test(u.pathname);
  } catch {
    return false;
  }
}

async function parseHtml(page, html, baseUrl) {
  return page.evaluate(({ html, baseUrl }) => {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const abs = value => {
      try { return new URL(value, baseUrl).href; } catch { return ''; }
    };
    const links = [...doc.querySelectorAll('a[href]')]
      .map(a => abs(a.getAttribute('href')))
      .filter(Boolean);
    const forms = [...doc.forms].map(form => ({
      action: abs(form.getAttribute('action') || baseUrl),
      method: (form.getAttribute('method') || 'GET').toUpperCase(),
      enctype: form.enctype || '',
      fields: [...form.elements].map(element => ({
        name: element.name || '',
        type: element.type || element.tagName.toLowerCase(),
        required: Boolean(element.required),
        has_value: Boolean(element.value),
      })),
    }));
    const assets = [...doc.querySelectorAll('script[src],link[href]')]
      .map(element => abs(element.getAttribute('src') || element.getAttribute('href')))
      .filter(Boolean);
    const inline = [...doc.scripts].filter(script => !script.src)
      .map(script => script.textContent || '').join('\n');
    const endpointPattern = /["'`]((?:\/|https:\/\/academy\.kisa\.or\.kr\/)[A-Za-z0-9_./?=&%{}:+~-]+(?:\.do|\.json|\.ajax|\.jsp|\.kisa|\.action)(?:\?[^"'`\s<>]*)?)["'`]/g;
    const endpoints = [];
    let match;
    while ((match = endpointPattern.exec(inline)) !== null) endpoints.push(abs(match[1]));
    const text = doc.body?.innerText || '';
    return {
      title: (doc.title || '').trim(),
      links: [...new Set(links)],
      forms,
      assets: [...new Set(assets)],
      endpoints: [...new Set(endpoints)],
      indicators: {
        login: /로그인/.test(text),
        logout: /로그아웃/.test(text),
        mypage: /마이페이지|수강신청\s*내역|나의\s*강의/.test(text),
        certificate: /수료증|이수증/.test(text),
      },
    };
  }, { html, baseUrl });
}

(async () => {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const portFile = path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'DevToolsActivePort');
  const [port, browserPath] = fs.readFileSync(portFile, 'utf8').split(/\r?\n/);
  const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${browserPath}`, { timeout: 10000 });
  const context = browser.contexts()[0];
  const parserPage = context.pages().find(page => {
    try { return new URL(page.url()).hostname === 'academy.kisa.or.kr'; } catch { return false; }
  });
  if (!parserPage) throw new Error('No academy.kisa.or.kr browser page is open');

  const seeds = [
    `${ORIGIN}/`,
    `${ORIGIN}/mypage/class/current.do`,
    parserPage.url(),
  ];
  const queue = seeds.map(url => ({ url: normalize(url, ORIGIN), depth: 0 }));
  const queued = new Set(queue.map(item => item.url));
  const visited = new Set();
  const pages = [];
  const forms = [];
  const assets = new Set();
  const endpoints = new Set();

  while (queue.length && visited.size < MAX_URLS) {
    const item = queue.shift();
    if (!item.url || visited.has(item.url) || !safeToFetch(item.url)) continue;
    visited.add(item.url);
    let response;
    try {
      response = await context.request.get(item.url, {
        maxRedirects: 0,
        timeout: 20000,
        headers: { 'User-Agent': USER_AGENT },
      });
    } catch (error) {
      pages.push({ url: redact(item.url), depth: item.depth, error: String(error) });
      continue;
    }
    const headers = response.headers();
    const body = await response.body();
    const contentType = headers['content-type'] || '';
    const record = {
      url: redact(item.url),
      depth: item.depth,
      status: response.status(),
      location: headers.location ? redact(normalize(headers.location, item.url) || headers.location) : '',
      content_type: contentType,
      length: body.length,
      sha256: crypto.createHash('sha256').update(body).digest('hex'),
      security_headers: {
        strict_transport_security: headers['strict-transport-security'] || '',
        content_security_policy: headers['content-security-policy'] || '',
        x_frame_options: headers['x-frame-options'] || '',
        x_content_type_options: headers['x-content-type-options'] || '',
      },
    };
    if (response.status() === 200 && /text\/html/i.test(contentType) && body.length <= 2_000_000) {
      const parsed = await parseHtml(parserPage, body.toString('utf8'), item.url);
      record.title = parsed.title;
      record.indicators = parsed.indicators;
      record.link_count = parsed.links.length;
      record.form_count = parsed.forms.length;
      for (const form of parsed.forms) {
        const safeForm = {
          source: redact(item.url),
          action: redact(normalize(form.action, item.url) || form.action),
          method: form.method,
          enctype: form.enctype,
          fields: form.fields,
        };
        forms.push(safeForm);
      }
      for (const asset of parsed.assets) {
        const normalized = normalize(asset, item.url);
        if (normalized) assets.add(redact(normalized));
      }
      for (const endpoint of parsed.endpoints) {
        const normalized = normalize(endpoint, item.url);
        if (normalized) endpoints.add(redact(normalized));
      }
      if (item.depth < MAX_DEPTH) {
        for (const link of parsed.links) {
          const normalized = normalize(link, item.url);
          if (!normalized || queued.has(normalized) || !safeToFetch(normalized)) continue;
          queued.add(normalized);
          queue.push({ url: normalized, depth: item.depth + 1 });
        }
      }
    }
    pages.push(record);
    await new Promise(resolve => setTimeout(resolve, 150));
  }

  const cookieMetadata = (await context.cookies(ORIGIN)).map(cookie => ({
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    session: cookie.expires === -1,
  }));
  const result = {
    target: ORIGIN,
    mode: 'authenticated-read-only-get-crawl',
    limits: { max_urls: MAX_URLS, max_depth: MAX_DEPTH, concurrency: 1 },
    cookie_metadata: cookieMetadata,
    pages,
    forms,
    assets: [...assets].sort(),
    inline_endpoints: [...endpoints].sort(),
  };
  fs.writeFileSync(path.join(OUT_DIR, 'authenticated-get-crawl.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({
    fetched: pages.length,
    status_counts: pages.reduce((acc, page) => { const key = page.status || 'error'; acc[key] = (acc[key] || 0) + 1; return acc; }, {}),
    forms: forms.length,
    assets: assets.size,
    inline_endpoints: endpoints.size,
    titles: pages.filter(page => page.title).map(page => ({ status: page.status, url: page.url, title: page.title })).slice(0, 80),
  }, null, 2));
  await browser.close();
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});

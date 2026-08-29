const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const ORIGIN = 'https://academy.kisa.or.kr';
const OUT_DIR = 'runs/20260829-011528-academy.kisa.or.kr-706647/raw/manual-auth';
const TARGETS = [
  '/mypage/class/current.do',
  '/mypage/class/learning.do',
  '/mypage/class/completion.do',
  '/mypage/class/cer.do',
  '/mypage/apply/current.do',
  '/mypage/qna.do',
  '/mypage/memModify.do',
  '/mypage/leave.do',
];

function redactUrlish(value) {
  return value
    .replace(/([?&](?:SQ|nttId|atchFileId|fileSn|EXM_CD|oid|mKey|mid|userId|memberId|qnaId)=)[^&'"\s)]+/gi, '$1<redacted>')
    .replace(/\b\d{4,}\b/g, '<number>');
}

function safeAttribute(value) {
  const call = value.match(/^(?:javascript:)?\s*([A-Za-z_$][\w$]*)\s*\(/i);
  if (call) return `${call[1]}(<arguments-redacted>)`;
  return redactUrlish(value);
}

function attributeValue(tag, name) {
  const quoted = tag.match(new RegExp(`\\b${name}\\s*=\\s*(["'])(.*?)\\1`, 'i'));
  if (quoted) return quoted[2];
  const bare = tag.match(new RegExp(`\\b${name}\\s*=\\s*([^\\s>]+)`, 'i'));
  return bare ? bare[1] : '';
}

function inputMetadata(html) {
  return [...html.matchAll(/<input\b[^>]*>/gi)]
    .map(match => {
      const tag = match[0];
      let name = attributeValue(tag, 'name');
      const type = attributeValue(tag, 'type') || 'text';
      const value = attributeValue(tag, 'value');
      if (/^\d{4}[-./]\d{1,2}[-./]\d{1,2}$/.test(name)) name = '<redacted-field-name>';
      let valueClass = 'empty';
      if (value) {
        if (/^\d+$/.test(value)) valueClass = 'digits';
        else if (/^[a-f0-9]+$/i.test(value)) valueClass = 'hex';
        else if (/^https?:\/\//i.test(value)) valueClass = 'url';
        else if (/^[A-Za-z0-9+/=_-]+$/.test(value)) valueClass = 'token-like';
        else valueClass = 'text';
      }
      return {
        name,
        type,
        value_present: Boolean(value),
        value_length: value.length,
        value_class: valueClass,
      };
    })
    .filter(item => item.name);
}

(async () => {
  const portFile = path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'DevToolsActivePort');
  const [port, browserPath] = fs.readFileSync(portFile, 'utf8').split(/\r?\n/);
  const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${browserPath}`, { timeout: 10000 });
  const context = browser.contexts()[0];
  const parserPage = context.pages().find(page => {
    try { return new URL(page.url()).hostname === 'academy.kisa.or.kr'; } catch { return false; }
  });
  if (!parserPage) throw new Error('No Academy page is open');

  const results = [];
  for (const targetPath of TARGETS) {
    const response = await context.request.get(`${ORIGIN}${targetPath}`, {
      maxRedirects: 0,
      timeout: 20000,
      headers: { 'User-Agent': 'authorized-recon-readonly/1.0' },
    });
    const body = await response.body();
    const html = body.toString('utf8');
    const parsed = await parserPage.evaluate(htmlValue => {
      const documentValue = new DOMParser().parseFromString(htmlValue, 'text/html');
      const attributes = [];
      for (const element of documentValue.querySelectorAll('[onclick],[href],[action]')) {
        for (const attribute of ['onclick', 'href', 'action']) {
          const value = element.getAttribute(attribute);
          if (value && /\.do|\.json|SQ|nttId|atchFile|cancel|exam|cer|signature|Account/i.test(value)) {
            attributes.push({ attribute, value });
          }
        }
      }
      const scripts = [...documentValue.scripts]
        .filter(script => !script.src)
        .map(script => script.textContent || '')
        .join('\n');
      const endpointPattern = /(?:https:\/\/academy\.kisa\.or\.kr)?\/[A-Za-z0-9_./-]+\.(?:do|json|jsp|ajax)(?:\?[^'"`\s<>]*)?/gi;
      const endpoints = [...scripts.matchAll(endpointPattern)].map(match => match[0]);
      const keyReferences = [];
      for (const line of scripts.split(/\r?\n/)) {
        if (!/getSignature|getAccountData|cerDetail|qnaDetail|cancelEdu|preExam|pssExam|pstExam|FileDown|memEnd|leaveEnd|\.ajax\s*\(|\$\.ajax/i.test(line)) continue;
        const functionName = (line.match(/function\s+([\w$]+)/) || line.match(/([\w$]+)\s*=\s*function/) || [])[1] || '';
        const lineEndpoints = [...line.matchAll(endpointPattern)].map(match => match[0]);
        keyReferences.push({ function_name: functionName, endpoints: lineEndpoints });
      }
      return {
        attributes,
        endpoints: [...new Set(endpoints)],
        key_references: keyReferences,
      };
    }, html);

    const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]
      ?.replace(/<[^>]*>|\s+/g, ' ').trim() || '';
    results.push({
      path: targetPath,
      status: response.status(),
      length: body.length,
      title,
      endpoint_strings: [...new Set(parsed.endpoints.map(redactUrlish))],
      event_attributes: parsed.attributes.map(item => ({
        attribute: item.attribute,
        value: safeAttribute(item.value),
      })),
      key_script_references: parsed.key_references.map(item => ({
        function_name: item.function_name,
        endpoints: item.endpoints.map(redactUrlish),
      })),
      input_metadata: inputMetadata(html),
    });
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, 'protected-structure-redacted.json'), JSON.stringify(results, null, 2) + '\n');
  console.log(JSON.stringify(results.map(item => ({
    path: item.path,
    endpoints: item.endpoint_strings,
    event_attributes: item.event_attributes.slice(0, 40),
    key_script_references: item.key_script_references,
    input_names: item.input_metadata.map(input => input.name),
  })), null, 2));
  await browser.close();
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});

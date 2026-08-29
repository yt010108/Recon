const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const ORIGIN = 'https://academy.kisa.or.kr';
const OUT = 'runs/20260829-011528-academy.kisa.or.kr-706647/raw/manual-auth/protected-script-snippets-redacted.json';
const TARGETS = [
  { path: '/mypage/class/current.do', patterns: ['getSignature.do', 'getAccountData.do', 'cancelEdu.do'] },
  { path: '/mypage/apply/current.do', patterns: ['getSignature.do', 'getAccountData.do', 'cancelEdu.do'] },
  { path: '/mypage/memModify.do', patterns: ['memEnd.do', 'issueVerificationCode.do', 'checkVerificationCode.do'] },
  { path: '/mypage/leave.do', patterns: ['actionLogout.do', 'leaveEnd.do'] },
  { path: '/mypage/class/cer.do', patterns: ['cerDetail.do'] },
  { path: '/mypage/qna.do', patterns: ['qnaDetail.do', 'FileDown.do'] },
];

function redact(line) {
  return line
    .replace(/value\s*=\s*(["']).*?\1/gi, 'value=<redacted>')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '<redacted-email>')
    .replace(/\b(?:01\d[- ]?\d{3,4}[- ]?\d{4})\b/g, '<redacted-phone>')
    .replace(/\b\d{4}[-./]\d{1,2}[-./]\d{1,2}\b/g, '<redacted-date>')
    .replace(/([?&](?:SQ|nttId|atchFileId|fileSn|oid|mKey|mid)=)[^&'"\s)]+/gi, '$1<redacted>')
    .replace(/\b\d{6,}\b/g, '<number>');
}

(async () => {
  const portPath = path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'DevToolsActivePort');
  const [port, browserPath] = fs.readFileSync(portPath, 'utf8').split(/\r?\n/);
  const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${browserPath}`);
  const context = browser.contexts()[0];
  const output = [];
  for (const target of TARGETS) {
    const response = await context.request.get(`${ORIGIN}${target.path}`, { maxRedirects: 0, timeout: 20000 });
    const lines = (await response.text()).split(/\r?\n/);
    const snippets = [];
    const seen = new Set();
    for (const pattern of target.patterns) {
      for (let index = 0; index < lines.length; index += 1) {
        if (!lines[index].includes(pattern)) continue;
        const start = Math.max(0, index - 12);
        const end = Math.min(lines.length, index + 13);
        const key = `${start}:${end}`;
        if (seen.has(key)) continue;
        seen.add(key);
        snippets.push({
          pattern,
          start_line: start + 1,
          lines: lines.slice(start, end).map(redact),
        });
      }
    }
    output.push({ path: target.path, status: response.status(), snippets });
  }
  fs.writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');
  console.log(JSON.stringify(output, null, 2));
  await browser.close();
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});

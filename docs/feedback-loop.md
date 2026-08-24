# Recon 피드백 루프 검토

## 결론

현재의 제한된 URL 재귀가 이 하네스에 맞는 피드백 루프다. 별도 이벤트 버스,
상시 daemon, AI 판단 단계는 넣지 않는다.

현재 흐름은 다음과 같다.

```text
Wayback / robots / Katana / source
                ↓
       in-scope URL queue
                ↓
        새 URL만 HTTPX
                ↓
 새 live origin·HTML만 Katana
                ↓
       새 URL을 queue로 반환
```

새 항목이 없으면 종료하고, 전체 흐름은 최대 2회다. URL·origin·Katana seed
상한도 함께 적용하므로 재귀가 요청 폭증으로 이어지지 않는다.

## 다른 구현에서 가져온 원칙

- BBOT은 모듈이 이벤트를 소비하고 새 이벤트를 다시 내보내는 방식으로 입력이
  없어질 때까지 반복한다. 동시에 재귀 도구끼리 서로 증폭할 수 있다고 경고하며
  scope distance와 노드 수 제한을 둔다.
- reconFTW는 JS·crawl에서 새 호스트를 찾으면 새 항목만 다시 HTTPX에 넣는다.
  무거운 재귀는 DEEP 모드와 깊이 설정으로 분리하고, monitor에서는 이전 결과와의
  delta를 따로 보존한다.
- HTTPX와 Katana 자체도 list 입력, scope, rate limit을 제공한다. 하네스는 이를
  새 항목에만 적용하고 상위에서 한 번 더 수량을 제한한다.

## 지금 넣지 않을 것

- BBOT식 범용 event bus: 현재 도구 수에는 구조가 너무 크다.
- 무제한 host·URL 재투입: 정보량보다 중복 요청이 더 빨리 증가한다.
- 자동 상시 monitor·알림: 일회성 Pi 하네스의 책임을 벗어난다.
- 점수나 AI로 다음 도구 선택: 재현성과 감사 가능성을 낮춘다.

## 다음 후보

필요해질 때 가장 작은 확장은 cross-run delta 보고다. 직전 run과 현재 run의
in-scope host·URL 집합만 비교해 `new`와 `removed`를 `report.md`에 표시하면 된다.
재스캔이나 알림은 자동화하지 않고 사용자가 새 run을 실행했을 때만 계산하는 편이
현재 구조와 맞다.

## 참고

- [BBOT events](https://github.com/blacklanternsecurity/bbot/blob/stable/docs/scanning/events.md)
- [BBOT scan sanity](https://www.blacklanternsecurity.com/bbot/Stable/scanning/scan_sanity/)
- [reconFTW changelog](https://github.com/six2dez/reconftw/blob/main/CHANGELOG.md)
- [HTTPX usage](https://docs.projectdiscovery.io/opensource/httpx/usage)
- [Katana running](https://docs.projectdiscovery.io/opensource/katana/running)

---
description: 허용 URL, 도메인 또는 IP로 리콘을 시작한다
---

먼저 전체 자동과 구간 수동 중 하나를 채팅으로 묻는다. 그다음 대상과 도메인 탐색 전체 제한시간을 한 번 묻는다. 단위는 초이고 기본값과 최대값은 180초다. Collect의 Subfinder, Assetfinder, Amass, Waybackurls는 병렬 실행한다. 구간 수동이면 collect 결과를 보여준 뒤 다음 단계 진행 여부를 매번 확인한다. Nuclei는 사용자가 요청했을 때만 단독 실행한다.

요청된 스코프 입력: `${ARGUMENTS:-제공되지 않음}`

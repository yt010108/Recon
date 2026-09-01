---
description: 허용 URL, 도메인 또는 IP로 리콘을 시작한다
---

먼저 전체 자동과 구간 수동 중 하나를 채팅으로 묻는다. 그다음 대상과 도메인 탐색 전체 제한시간을 한 번 묻는다. 전체 자동이면 Gobuster 사용 여부를 묻는다. Parameth는 자동 실행하지 않고 Discovery가 만든 후보 중 사용자가 URL을 선택했을 때만 실행한다. 각 단계는 자체 report.md를 만들고 루트 report.md는 Normalize 후 최종본으로 사용한다. Nuclei는 사용자가 요청했을 때만 단독 실행한다.

요청된 스코프 입력: `${ARGUMENTS:-제공되지 않음}`

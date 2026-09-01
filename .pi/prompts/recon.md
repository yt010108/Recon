---
description: 허용 URL, 도메인 또는 IP로 리콘을 시작한다
---

허용 URL, 도메인 또는 IP 하나만 묻고 `recon_start`로 전체 리콘을 실행한다. 수집기는 모두 유지하고 normalize 결과의 상위 후보부터 보여준다. Nuclei는 사용자가 요청했을 때만 단독 실행한다. 기존 run ID가 있으면 그 run에 누적한다.

요청된 스코프 입력: `${ARGUMENTS:-제공되지 않음}`

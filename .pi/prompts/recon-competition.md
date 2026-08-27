---
description: 허용된 내부 IPv4/CIDR로 대회용 리콘을 시작한다
---

사용자에게 대회에서 명시적으로 허용된 IPv4 주소 또는 CIDR만 받는다. 포트 범위를 별도로 주면 그대로 사용하고, 없으면 하네스의 공통 웹 포트를 사용해 `recon_competition_start`를 실행한다. 스코프는 자동으로 확대하지 않는다. Nuclei는 전체 실행에 넣지 않으며 사용자가 요청했을 때만 `recon_run`으로 단독 실행한다. 완료되면 run ID, 활성 웹 서비스 수, `report.md`, `parsed/attack-surface.json` 위치를 짧게 알려준다.

요청된 스코프 입력: `${ARGUMENTS:-제공되지 않음}`

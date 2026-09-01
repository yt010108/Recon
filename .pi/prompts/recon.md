---
description: 허용 IPv4/CIDR과 포트로 대회용 웹 리콘을 시작한다
---

허용 IPv4/CIDR과 포트, fast/deep 프로필을 확인한다. `recon_create` 후 inventory, mapping, normalize를 순서대로 호출해 진행 상태를 보여준다. deep 프로필에서만 expansion을 실행한다. Nuclei는 사용자가 요청했을 때만 단독 실행한다. 완료되면 상위 후보, 실패 영역과 run ID를 알려준다.

요청된 스코프 입력: `${ARGUMENTS:-제공되지 않음}`

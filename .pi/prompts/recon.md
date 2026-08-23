---
description: 허용 도메인 하나로 리콘을 시작한다
---

허용 도메인 하나만 묻고 `recon_start`로 전체 리콘을 실행한다. Nuclei는 전체 실행에 넣지 않으며 사용자가 요청했을 때 `recon_create`와 `recon_run`으로 단독 실행한다. 특정 단계나 도구 요청도 같은 방식으로 처리하고, 기존 run ID가 있으면 그 run에 누적한다. 완료되면 짧은 요약과 run ID를 알려준다.

요청된 스코프 입력: `${ARGUMENTS:-제공되지 않음}`

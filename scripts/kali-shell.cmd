@echo off
setlocal
set "STATUS="
for /f "delims=" %%S in ('docker inspect -f "{{.State.Status}}" kali 2^>nul') do set "STATUS=%%S"
if not defined STATUS (
  echo Container 'kali' was not found.
  exit /b 1
)
if /I "%STATUS%"=="running" (
  docker exec -it kali /bin/bash
) else (
  docker start -ai kali
)
endlocal

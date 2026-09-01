#!/usr/bin/env python3
"""Generate Google dork queries without sending requests to Google."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import webbrowser
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import quote_plus, urlsplit


VERSION = "1.0.0"

# Add or remove templates here. Each template must contain a ``{domain}`` field.
# The order is preserved in the generated output.
DORK_TEMPLATES = (
    # Basic assets
    "site:{domain}",
    "site:*.{domain} -www.{domain}",
    "site:{domain} inurl:www",
    "site:{domain} inurl:portal",
    "site:{domain} inurl:dashboard",
    # Login and administration pages
    "site:{domain} inurl:admin",
    "site:{domain} inurl:administrator",
    "site:{domain} inurl:admin/login",
    "site:{domain} inurl:login",
    "site:{domain} inurl:signin",
    "site:{domain} inurl:auth",
    "site:{domain} intitle:\"admin\"",
    "site:{domain} intitle:\"login\"",
    # API and development pages
    "site:{domain} inurl:api",
    "site:{domain} inurl:/api/",
    "site:{domain} inurl:/v1/",
    "site:{domain} inurl:/v2/",
    "site:{domain} inurl:developer",
    "site:{domain} inurl:dev",
    "site:{domain} inurl:staging",
    "site:{domain} inurl:test",
    "site:{domain} inurl:sandbox",
    # Swagger, OpenAPI, and GraphQL
    "site:{domain} inurl:swagger",
    "site:{domain} inurl:swagger-ui",
    "site:{domain} inurl:api-docs",
    "site:{domain} inurl:openapi",
    "site:{domain} filetype:json inurl:swagger",
    "site:{domain} filetype:json inurl:openapi",
    "site:{domain} inurl:graphql",
    "site:{domain} inurl:graphiql",
    # Documents and data files
    "site:{domain} filetype:pdf",
    "site:{domain} filetype:doc",
    "site:{domain} filetype:docx",
    "site:{domain} filetype:xls",
    "site:{domain} filetype:xlsx",
    "site:{domain} filetype:csv",
    "site:{domain} filetype:ppt",
    "site:{domain} filetype:pptx",
    "site:{domain} filetype:txt",
    "site:{domain} filetype:xml",
    "site:{domain} filetype:json",
    # Documentation portals
    "site:{domain} inurl:docs",
    "site:{domain} inurl:documentation",
    "site:{domain} inurl:wiki",
    "site:{domain} inurl:manual",
    "site:{domain} intitle:\"documentation\"",
    # Directory listings and uploads
    "site:{domain} intitle:\"index of\"",
    "site:{domain} intitle:\"index of\" \"parent directory\"",
    "site:{domain} intitle:\"index of\" \"backup\"",
    "site:{domain} intitle:\"index of\" \"upload\"",
    "site:{domain} inurl:uploads",
    "site:{domain} inurl:files",
    # Errors and debug output
    "site:{domain} \"SQL syntax\"",
    "site:{domain} \"Warning: mysql\"",
    "site:{domain} \"Fatal error\"",
    "site:{domain} \"stack trace\"",
    "site:{domain} \"Traceback (most recent call last)\"",
    "site:{domain} inurl:debug",
    "site:{domain} intitle:\"error\"",
    "site:{domain} intitle:\"exception\"",
    # Backups and configuration files
    "site:{domain} (ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:save OR ext:swp)",
    "site:{domain} (inurl:backup OR inurl:backups)",
    "site:{domain} (inurl:.git OR inurl:.svn)",
    "site:{domain} (ext:env OR ext:ini OR ext:conf OR ext:config)",
    "site:{domain} (ext:yml OR ext:yaml) (inurl:config OR inurl:settings)",
    "site:{domain} (\"DB_PASSWORD\" OR \"DATABASE_URL\" OR \"API_KEY\")",
)


class DomainError(ValueError):
    """Raised when a target cannot be normalized to a valid domain."""


class Colors:
    """Small ANSI color helper that enables colors only for a terminal."""

    def __init__(self, stream: object = sys.stdout) -> None:
        enabled = bool(getattr(stream, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ
        self.bold = "\033[1m" if enabled else ""
        self.cyan = "\033[36m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.reset = "\033[0m" if enabled else ""


def normalize_domain(value: str) -> str:
    """Return a validated, lowercase ASCII domain from a URL-like input."""

    raw = value.strip()
    if not raw:
        raise DomainError("대상 도메인이 비어 있습니다.")
    if any(character.isspace() for character in raw):
        raise DomainError("도메인에는 공백을 사용할 수 없습니다.")

    has_scheme = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", raw) is not None
    candidate = raw if has_scheme else f"//{raw}"

    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise DomainError("URL 형식을 해석할 수 없습니다.") from exc

    if has_scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise DomainError("http:// 또는 https:// 주소만 사용할 수 있습니다.")
    if parsed.username is not None or parsed.password is not None:
        raise DomainError("사용자 정보가 포함된 URL은 사용할 수 없습니다.")

    try:
        # Accessing .port also validates malformed or out-of-range ports.
        _ = parsed.port
    except ValueError as exc:
        raise DomainError("포트 번호가 올바르지 않습니다.") from exc

    hostname = parsed.hostname
    if not hostname:
        raise DomainError("URL에서 도메인을 찾을 수 없습니다.")

    hostname = hostname.rstrip(".").lower()
    if "*" in hostname:
        raise DomainError("와일드카드 대신 기준 도메인만 입력하세요.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise DomainError("IP 주소가 아닌 도메인을 입력하세요.")

    try:
        ascii_domain = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainError("국제화 도메인 형식이 올바르지 않습니다.") from exc

    if len(ascii_domain) > 253:
        raise DomainError("도메인이 너무 깁니다.")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise DomainError("example.com과 같은 완전한 도메인을 입력하세요.")

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise DomainError("도메인 라벨 형식이 올바르지 않습니다.")
    if labels[-1].isdigit():
        raise DomainError("최상위 도메인 형식이 올바르지 않습니다.")

    return ascii_domain


def generate_dorks(domain: str, templates: Iterable[str] = DORK_TEMPLATES) -> list[str]:
    """Generate dorks while removing duplicates and preserving their order."""

    generated: list[str] = []
    seen: set[str] = set()

    for template in templates:
        dork = template.format(domain=domain).strip()
        if dork and dork not in seen:
            seen.add(dork)
            generated.append(dork)

    return generated


def as_google_urls(dorks: Iterable[str]) -> list[str]:
    """Convert queries into encoded Google search URLs without requesting them."""

    return [f"https://www.google.com/search?q={quote_plus(dork)}" for dork in dorks]


def browse_dorks(dorks: Sequence[str], colors: Colors) -> None:
    """Let the user explicitly open selected searches in their default browser."""

    print(
        f"\n{colors.bold}{colors.cyan}브라우저 검색 모드{colors.reset}\n"
        "목록 번호를 입력하면 해당 Google 검색 결과를 기본 브라우저에서 엽니다.\n"
        "여러 개를 보려면 한 번에 하나씩 입력하세요. Enter를 누르면 종료합니다."
    )

    while True:
        try:
            choice = input(f"\n열 검색식 번호 [1-{len(dorks)}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n브라우저 검색 모드를 종료합니다.")
            return

        if not choice:
            print("브라우저 검색 모드를 종료합니다.")
            return
        if not choice.isdigit():
            print("숫자 하나만 입력하세요.", file=sys.stderr)
            continue

        index = int(choice)
        if not 1 <= index <= len(dorks):
            print(f"1부터 {len(dorks)} 사이의 번호를 입력하세요.", file=sys.stderr)
            continue

        search_url = as_google_urls([dorks[index - 1]])[0]
        print(f"여는 중: {dorks[index - 1]}")
        if not webbrowser.open(search_url, new=2):
            print("브라우저를 자동으로 열 수 없습니다. 아래 URL을 직접 여세요:")
            print(search_url)


def save_dorks(lines: Iterable[str], output: str | Path) -> Path:
    """Save generated lines as UTF-8 text and return the resolved output path."""

    destination = Path(output).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination.resolve()


def build_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="dorkgen.py",
        description=(
            "대상 도메인의 Google Dork 검색식만 생성합니다. "
            "Google 요청이나 검색 결과 수집은 수행하지 않습니다."
        ),
        epilog=(
            "예시:\n"
            "  python3 dorkgen.py example.com\n"
            "  python3 dorkgen.py https://example.com/path --output dorks.txt\n"
            "  python3 dorkgen.py example.com --urls\n"
            "  python3 dorkgen.py              # 대화형 안내 모드\n\n"
            "본인이 소유하거나 명시적으로 허가받은 대상에만 사용하세요."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="대상 도메인 또는 URL (생략하면 대화형 안내 모드)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="생성 결과를 저장할 UTF-8 텍스트 파일",
    )
    parser.add_argument(
        "--urls",
        action="store_true",
        help="검색식 대신 URL-encoded Google 검색 URL을 출력",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="목록에서 번호를 선택해 실제 Google 검색 결과를 브라우저로 열기",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="제목, 번호, 요약 없이 결과만 출력",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def guided_input(colors: Colors) -> tuple[str, bool, str | None, bool]:
    """Collect target and output preferences in an interactive terminal."""

    print(f"{colors.bold}{colors.cyan}Google Dork Generator {VERSION}{colors.reset}")
    print("검색식 생성 전용 도구입니다. Google 접속이나 결과 수집은 하지 않습니다.")
    print("허가된 버그바운티, CTF 또는 모의해킹 대상에만 사용하세요.\n")

    domain = input(f"{colors.bold}대상 도메인 또는 URL{colors.reset}: ").strip()
    format_choice = input("출력 형식 [1: 검색식, 2: Google URL] (기본 1): ").strip()
    if format_choice not in {"", "1", "2"}:
        raise ValueError("출력 형식은 1 또는 2를 선택하세요.")

    output = input("저장할 .txt 파일 경로 (저장하지 않으려면 Enter): ").strip()
    open_choice = input("검색 결과를 브라우저에서 직접 볼까요? [y/N]: ").strip().lower()
    if open_choice not in {"", "n", "no", "y", "yes"}:
        raise ValueError("브라우저 실행 여부는 y 또는 n으로 입력하세요.")

    return domain, format_choice == "2", output or None, open_choice in {"y", "yes"}


def print_results(
    domain: str,
    lines: Sequence[str],
    *,
    url_mode: bool,
    quiet: bool,
    colors: Colors,
) -> None:
    """Print generated output to the terminal."""

    if quiet:
        print("\n".join(lines))
        return

    mode = "Google URLs" if url_mode else "Dork queries"
    print(f"\n{colors.bold}Target:{colors.reset} {colors.cyan}{domain}{colors.reset}")
    print(f"{colors.bold}Mode:{colors.reset} {mode}\n")
    for index, line in enumerate(lines, start=1):
        print(f"{colors.yellow}[{index}]{colors.reset} {line}")
    print(f"\n{colors.green}Generated {len(lines)} dorks.{colors.reset}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""

    parser = build_parser()
    args = parser.parse_args(argv)
    colors = Colors()

    if args.domain is None:
        if args.quiet or not sys.stdin.isatty():
            parser.error("대상 도메인을 입력하세요. 예: python3 dorkgen.py example.com")
        try:
            args.domain, guided_urls, guided_output, guided_open = guided_input(colors)
        except (EOFError, KeyboardInterrupt):
            print("\n입력이 취소되었습니다.", file=sys.stderr)
            return 130
        except ValueError as exc:
            parser.error(str(exc))
        args.urls = args.urls or guided_urls
        args.output = args.output or guided_output
        args.open = args.open or guided_open

    if args.open and (args.quiet or not sys.stdin.isatty()):
        parser.error("--open은 번호를 선택할 수 있는 대화형 터미널에서 사용하세요.")

    try:
        domain = normalize_domain(args.domain)
    except DomainError as exc:
        parser.error(str(exc))

    dorks = generate_dorks(domain)
    output_lines = as_google_urls(dorks) if args.urls else dorks
    print_results(
        domain,
        output_lines,
        url_mode=args.urls,
        quiet=args.quiet,
        colors=colors,
    )

    if args.output:
        try:
            destination = save_dorks(output_lines, args.output)
        except OSError as exc:
            print(f"파일 저장 실패: {exc}", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"{colors.green}Saved:{colors.reset} {destination}")

    if args.open:
        browse_dorks(dorks, colors)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

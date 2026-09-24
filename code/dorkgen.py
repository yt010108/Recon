"""Generate Google dork queries without sending requests to Google."""

from __future__ import annotations

from typing import Iterable


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

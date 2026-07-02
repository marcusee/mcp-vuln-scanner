from collections import defaultdict

def rollup_all_cves(components: list[dict]) -> dict[str, list[tuple[str, dict]]]:
    """purl -> list of (origin_purl, issue) for itself and all descendants."""
    own_issues = {}               # purl -> list of its own issue dicts
    parents = {}                  # purl -> parent purls

    for c in components:
        purl = c["packageUrl"]
        issues = (c.get("securityData") or {}).get("securityIssues") or []
        own_issues[purl] = issues
        parents[purl] = (c.get("dependencyData") or {}).get("parentComponentPurls") or []

    # rolled[purl] = set of (origin_purl, issue_ref) — use reference/id, dicts aren't hashable
    rolled = defaultdict(set)

    for purl, issues in own_issues.items():
        if not issues:
            continue
        tagged = {(purl, i.get("reference", i.get("source", str(idx))))
                  for idx, i in enumerate(issues)}
        rolled[purl] |= tagged
        # walk up to every ancestor, same pattern as before
        stack, seen = list(parents[purl]), set()
        while stack:
            p = stack.pop()
            if p in seen:
                continue
            seen.add(p)
            rolled[p] |= tagged
            stack.extend(parents.get(p, []))

    # resolve references back to full issue dicts
    issue_lookup = {
        (purl, i.get("reference", i.get("source", str(idx)))): i
        for purl, issues in own_issues.items()
        for idx, i in enumerate(issues)
    }
    return {
        purl: [(origin, issue_lookup[(origin, ref)]) for origin, ref in refs]
        for purl, refs in rolled.items()
    }

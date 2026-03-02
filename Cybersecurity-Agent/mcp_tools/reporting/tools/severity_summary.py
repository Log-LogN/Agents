def severity_summary(cve_list: list) -> dict:
    summary = {}

    for cve in cve_list:
        sev = cve.get("severity", "UNKNOWN")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "severity_distribution": summary
    }
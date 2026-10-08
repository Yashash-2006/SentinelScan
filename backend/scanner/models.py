from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    owasp: str
    evidence: str
    url: str
    remediation: str
    check: str
    def to_dict(self):
        return asdict(self)

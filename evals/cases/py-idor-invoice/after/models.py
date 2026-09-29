from dataclasses import dataclass, field

_TOKENS = {}
_INVOICES = {}


@dataclass
class User:
    id: int
    tenant_id: int

    @staticmethod
    def from_token(token):
        return _TOKENS.get(token)


@dataclass
class Invoice:
    id: int
    tenant_id: int
    total_cents: int
    lines: list = field(default_factory=list)

    @staticmethod
    def get(invoice_id):
        return _INVOICES.get(invoice_id)

    def to_dict(self, include_lines=False):
        data = {"id": self.id, "total_cents": self.total_cents}
        if include_lines:
            data["lines"] = list(self.lines)
        return data

from dataclasses import dataclass

@dataclass
class Account:
    role: str
    is_staff: bool
    is_active: bool = True
    is_authenticated: bool = True

OPERATOR = Account(role="operator", is_staff=True)
ADMINISTRATOR = Account(role="administrator", is_staff=True)

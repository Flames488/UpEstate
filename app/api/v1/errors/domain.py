class DomainError(Exception):
    pass

class ValidationError(DomainError):
    pass

class PermissionDenied(DomainError):
    pass

class PermissionService:
    ROLE_HIERARCHY = {
        "user": 1,
        "admin": 5,
        "superadmin": 10,
    }

    PLAN_FEATURES = {
        "free": {"view_dashboard"},
        "pro": {"view_dashboard", "lead_scoring"},
        "enterprise": {
            "view_dashboard",
            "lead_scoring",
            "automation",
            "priority_support",
        },
    }

    @staticmethod
    def has_role(user, required_role: str) -> bool:
        return (
            PermissionService.ROLE_HIERARCHY.get(user.role, 0)
            >= PermissionService.ROLE_HIERARCHY.get(required_role, 0)
        )

    @staticmethod
    def has_feature(user, feature: str) -> bool:
        plan = user.subscription_plan
        return feature in PermissionService.PLAN_FEATURES.get(plan, set())

    @staticmethod
    def assert_feature(user, feature: str):
        if not PermissionService.has_feature(user, feature):
            raise PermissionError(f"Feature '{feature}' not allowed for plan")

    @staticmethod
    def assert_role(user, role: str):
        if not PermissionService.has_role(user, role):
            raise PermissionError(f"Role '{role}' required")

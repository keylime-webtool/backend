use serde::{Deserialize, Serialize};

/// Three-tier RBAC roles (SR-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

/// Permissions that can be checked against a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read dashboards, agents, policies, certs, audit logs.
    Read,
    /// Write operations: agent actions, policy drafts.
    Write,
    /// Approve policy changes, delete agents, configure thresholds.
    Approve,
    /// System configuration, user management.
    AdminConfig,
    /// Export data (CSV/JSON/PDF).
    Export,
}

impl Role {
    /// Check whether this role has the given permission.
    pub fn has_permission(self, perm: Permission) -> bool {
        match perm {
            Permission::Read => true,
            Permission::Write => matches!(self, Role::Operator | Role::Admin),
            Permission::Export => matches!(self, Role::Operator | Role::Admin),
            Permission::Approve | Permission::AdminConfig => matches!(self, Role::Admin),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_can_read_but_not_write() {
        assert!(Role::Viewer.has_permission(Permission::Read));
        assert!(!Role::Viewer.has_permission(Permission::Write));
        assert!(!Role::Viewer.has_permission(Permission::Export));
        assert!(!Role::Viewer.has_permission(Permission::Approve));
    }

    #[test]
    fn operator_can_write_but_not_approve() {
        assert!(Role::Operator.has_permission(Permission::Read));
        assert!(Role::Operator.has_permission(Permission::Write));
        assert!(Role::Operator.has_permission(Permission::Export));
        assert!(!Role::Operator.has_permission(Permission::Approve));
    }

    #[test]
    fn admin_has_all_permissions() {
        assert!(Role::Admin.has_permission(Permission::Read));
        assert!(Role::Admin.has_permission(Permission::Write));
        assert!(Role::Admin.has_permission(Permission::Export));
        assert!(Role::Admin.has_permission(Permission::Approve));
        assert!(Role::Admin.has_permission(Permission::AdminConfig));
    }
}

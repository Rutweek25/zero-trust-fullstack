import { Link, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import { getProfile } from "../api/api";

export default function AdminSidebar() {
  const location = useLocation();
  const [userRole, setUserRole] = useState(null);

  useEffect(() => {
    async function fetchRole() {
      try {
        const profile = await getProfile();
        setUserRole(profile?.role);
      } catch (error) {
        console.error("Failed to fetch user role:", error);
      }
    }
    fetchRole();
  }, []);

  function isActive(path) {
    return location.pathname === path;
  }

  const sidebarStyle = {
    width: "260px",
    backgroundColor: "#1a1a1a",
    color: "#fff",
    display: "flex",
    flexDirection: "column",
    padding: "20px 0",
    borderRight: "1px solid #333",
  };

  const logoStyle = {
    padding: "20px 20px",
    borderBottom: "1px solid #333",
    marginBottom: "30px",
    fontSize: "16px",
    fontWeight: "bold",
    color: "#fff",
  };

  const navItemStyle = (path) => ({
    padding: "12px 20px",
    margin: "8px 10px",
    borderRadius: "6px",
    textDecoration: "none",
    color: isActive(path) ? "#007bff" : "#aaa",
    backgroundColor: isActive(path) ? "rgba(0, 123, 255, 0.1)" : "transparent",
    borderLeft: isActive(path) ? "3px solid #007bff" : "3px solid transparent",
    transition: "all 0.3s",
    display: "flex",
    alignItems: "center",
    gap: "12px",
    fontSize: "14px",
    fontWeight: isActive(path) ? "600" : "500",
    cursor: "pointer",
  });

  return (
    <div style={sidebarStyle}>
      <div style={logoStyle}>
        🛡 Admin Portal
      </div>

      <nav style={{ flex: 1 }}>
        <Link to="/admin/profile" style={navItemStyle("/admin/profile")}>
          <span>👤</span> Profile
        </Link>
        <Link to="/admin/logs" style={navItemStyle("/admin/logs")}>
          <span>📋</span> Recent Logs
        </Link>
        <Link to="/admin/usb-events" style={navItemStyle("/admin/usb-events")}>
          <span>🔌</span> USB Events
        </Link>
        <Link to="/admin/login-history" style={navItemStyle("/admin/login-history")}>
          <span>🌍</span> Login History
        </Link>
        <Link to="/admin/users" style={navItemStyle("/admin/users")}>
          <span>👥</span> Users
        </Link>
        <Link to="/admin/user-management" style={navItemStyle("/admin/user-management")}>
          <span>🔐</span> User Management
        </Link>
        
        {/* Superadmin only */}
        {userRole === "superadmin" && (
          <Link to="/admin/pending-requests" style={navItemStyle("/admin/pending-requests")}>
            <span>📝</span> Pending Requests
          </Link>
        )}
      </nav>


    </div>
  );
}

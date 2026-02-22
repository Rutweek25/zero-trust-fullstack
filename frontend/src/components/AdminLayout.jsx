import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import AdminSidebar from "./AdminSidebar";
import { getProfile } from "../api/api";

export default function AdminLayout() {
  const location = useLocation();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);

  // Verify admin role with server on mount (do not trust localStorage role)
  useEffect(() => {
    let mounted = true;

    async function verify() {
      try {
        const res = await getProfile();

        // Backend returns user object directly: { id, username, role, ... }
        if (!mounted || !res) return;

        // Check if user has admin or superadmin role
        if (!res.role || (res.role !== "admin" && res.role !== "superadmin")) {
          navigate("/");
          return;
        }
      } catch (err) {
        console.error("Admin verification failed:", err);
        navigate("/");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    verify();

    return () => { mounted = false; };
  }, [navigate]);

  return (
    <div style={{ display: "flex", minHeight: "100vh", backgroundColor: "#f8f9fa" }}>
      <AdminSidebar />
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {/* Top bar */}
        <div style={{
          backgroundColor: "#fff",
          borderBottom: "1px solid #e0e0e0",
          padding: "16px 30px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          height: "60px"
        }}>
          <h2 style={{ margin: 0, fontSize: 20, color: "#1a1a1a", fontWeight: 600 }}>
            {getPageTitle(location.pathname)}
          </h2>
        </div>

        {/* Main content area */}
        <div style={{
          flex: 1,
          padding: "30px",
          overflowY: "auto"
        }}>
          {loading ? <div>Loading...</div> : <Outlet />}
        </div>
      </div>
    </div>
  );
}

function getPageTitle(pathname) {
  if (pathname === "/admin" || pathname === "/admin/profile") return "👤 Admin Profile";
  if (pathname === "/admin/logs") return "📋 Recent Logs";
  if (pathname === "/admin/usb-events") return "🔌 USB Events";
  if (pathname === "/admin/login-history") return "🌍 Login History";
  if (pathname === "/admin/users") return "👥 Users Management";
  if (pathname.includes("/admin/users/") && pathname.includes("/logs")) return "📋 User Activity Logs";
  return "🛡 Admin Dashboard";
}

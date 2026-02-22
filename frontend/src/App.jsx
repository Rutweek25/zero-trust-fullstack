import { Routes, Route, Link } from "react-router-dom";
import { useState, useEffect, useCallback } from "react";
import { getProfile } from "./api/api";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Admin from "./pages/Admin";
import AdminLayout from "./components/AdminLayout";
import AdminProfile from "./pages/admin/Profile";
import AdminLogs from "./pages/admin/Logs";
import AdminUsers from "./pages/admin/Users";
import AdminUserLogs from "./pages/admin/UserLogs";
import UserManagement from "./pages/admin/UserManagement";
import PendingRequests from "./pages/admin/PendingRequests";
import AdminUsbEvents from "./pages/admin/UsbEvents";
import LoginHistory from "./pages/admin/LoginHistory";
import LogoutBtn from "./components/LogoutBtn";

function App() {
  // Initialize isLoggedIn from localStorage to prevent flashing Login/Register links
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem("access_token"));
  const [user, setUser] = useState(null);
  const role = localStorage.getItem("role");

  const loadUserProfile = useCallback(async () => {
    try {
      const profileData = await getProfile();
      if (profileData && !profileData.detail) {
        setUser(profileData);
      }
    } catch {
      console.log("Failed to load user profile");
    }
  }, []);

  useEffect(() => {
    const token = localStorage.getItem("access_token");
    
    // Fetch user profile if logged in
    if (token) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      loadUserProfile();
    }

    const handleLogin = () => {
      setIsLoggedIn(true);
      loadUserProfile();
    };
    const handleLogoutEvent = () => {
      setIsLoggedIn(false);
      setUser(null);
    };

    window.addEventListener('login', handleLogin);
    window.addEventListener('logout', handleLogoutEvent);

    return () => {
      window.removeEventListener('login', handleLogin);
      window.removeEventListener('logout', handleLogoutEvent);
    };
  }, [loadUserProfile])

  return (
    <>
      {/* NAVBAR */}
      <nav style={{
        padding: "0 20px",
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '20px',
        backgroundColor: "#f8f9fa",
        borderBottom: "1px solid #e0e0e0",
        margin: 0,
        height: '60px'
      }}>
        {/* Logo/Brand */}
        <div style={{ fontWeight: 'bold', fontSize: '18px', color: '#1a1a1a' }}>
          🛡 Insider ZeroTrust
        </div>

        {/* User Info & Navigation */}
        <div style={{ display: 'flex', gap: '30px', alignItems: 'center' }}>
          {/* Show User ID when logged in */}
          {isLoggedIn && user && (
            <div style={{ 
              display: 'flex', 
              alignItems: 'center',
              gap: '10px',
              padding: '0 15px',
              borderRight: '1px solid #e0e0e0'
            }}>
              <span style={{ fontSize: '13px', color: '#666', fontWeight: 500 }}>ID:</span>
              <span style={{ fontSize: '14px', color: '#1a1a1a', fontWeight: 600, fontFamily: 'monospace' }}>
                {user.id}
              </span>
            </div>
          )}

          {/* Navigation Items */}
          <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
            {/* Show Dashboard & Admin Panel only when logged in */}
            {isLoggedIn && (
              <>
                <Link to="/dashboard" style={{ color: '#007bff', textDecoration: 'none', fontSize: '14px', fontWeight: 500 }}>
                  Dashboard
                </Link>
                {(role === "admin" || role === "superadmin") && (
                  <Link to="/admin" style={{ color: '#dc3545', textDecoration: 'none', fontSize: '14px', fontWeight: 500 }}>
                    ⚙️ Admin Panel
                  </Link>
                )}
                <LogoutBtn />
              </>
            )}
          </div>
        </div>
      </nav>

      {/* ROUTES */}
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/dashboard" element={<Dashboard />} />
        
        {/* Old Admin Page (for backward compatibility) */}
        <Route path="/admin-old" element={<Admin />} />

        {/* New Multi-page Admin Dashboard */}
        <Route element={<AdminLayout />}>
          <Route path="/admin" element={<AdminProfile />} />
          <Route path="/admin/profile" element={<AdminProfile />} />
          <Route path="/admin/logs" element={<AdminLogs />} />
          <Route path="/admin/usb-events" element={<AdminUsbEvents />} />
          <Route path="/admin/login-history" element={<LoginHistory />} />
          <Route path="/admin/users" element={<AdminUsers />} />
          <Route path="/admin/users/:userId/logs" element={<AdminUserLogs />} />
          <Route path="/admin/user-management" element={<UserManagement />} />
          <Route path="/admin/pending-requests" element={<PendingRequests />} />
        </Route>
      </Routes>
    </>
  );
}

export default App;

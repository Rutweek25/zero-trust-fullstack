const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

// ---------- Save tokens ----------
function saveTokens(access, refresh) {
  localStorage.setItem("access_token", access);
  localStorage.setItem("refresh_token", refresh);
}

export function getAccessToken() {
  return localStorage.getItem("access_token");
}

export function getRefreshToken() {
  return localStorage.getItem("refresh_token");
}

// ---------- Auto Request Handler (with refresh support) ----------
async function authFetch(url, options = {}) {
  let token = getAccessToken();

  options.headers = {
    ...(options.headers || {}),
    "Content-Type": "application/json",
    "Authorization": `Bearer ${token}`
  };

  let res = await fetch(url, options);

  // If token expired -> generate new one using refresh_token
  if (res.status === 401 && getRefreshToken()) {
    console.log("🔄 Access token expired — refreshing...");
    const refreshRes = await refreshToken();

    if (refreshRes.success) {
      token = refreshRes.access_token;
      options.headers["Authorization"] = `Bearer ${token}`;

      // Retry original request
      res = await fetch(url, options);
    } else {
      console.log("⛔ Refresh failed — redirect login required");
      localStorage.clear();
      window.location.href = "/login";
    }
  }

  return res.json();
}

// ---------- REGISTER USER ----------
export async function registerUser(data) {
  const res = await fetch(`${API_BASE}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });

  const result = await res.json();
  return res.ok ? { success: true, user: result } : { success: false, message: result.detail };
}

// ---------- LOGIN USER ----------
export async function loginUser(data) {
  const res = await fetch(`${API_BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });

  const result = await res.json();

  if (res.ok) {
    saveTokens(result.access_token, result.refresh_token);
    localStorage.setItem("role", result.role);
    localStorage.setItem("username", result.username);

    return { success: true, user: result };
  }

  // Handle validation errors (422) and other errors
  const errorMessage = result.detail 
    ? (typeof result.detail === 'string' ? result.detail : JSON.stringify(result.detail))
    : 'Login failed';

  return { success: false, message: errorMessage };
}

export async function loginWithMicrosoft(token) {
  const res = await fetch(`${API_BASE}/login/microsoft`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token })
  });

  const result = await res.json();

  if (res.ok && result.access_token) {
    saveTokens(result.access_token, result.refresh_token);
    localStorage.setItem("role", result.role);
    localStorage.setItem("username", result.username);
    localStorage.setItem("loginType", "microsoft");
    return { success: true, user: result };
  }

  const errorMessage = result.detail
    ? (typeof result.detail === "string" ? result.detail : JSON.stringify(result.detail))
    : "Microsoft login failed";

  console.error("[Microsoft OAuth] Backend response", {
    status: res.status,
    detail: result.detail || result
  });

  return { success: false, message: errorMessage };
}

export async function loginWithGoogle(token) {
  const res = await fetch(`${API_BASE}/login/google`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token })
  });

  const result = await res.json();

  if (res.ok && result.access_token) {
    saveTokens(result.access_token, result.refresh_token);
    localStorage.setItem("role", result.role);
    localStorage.setItem("username", result.username);
    localStorage.setItem("loginType", "google");
    return { success: true, user: result };
  }

  const errorMessage = result.detail
    ? (typeof result.detail === "string" ? result.detail : JSON.stringify(result.detail))
    : "Google login failed";

  return { success: false, message: errorMessage };
}

// ---------- Refresh Token ----------
export async function refreshToken() {
  const refresh = getRefreshToken();

  const res = await fetch(`${API_BASE}/refresh-token?token=${refresh}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  });

  const data = await res.json();

  if (res.ok && data.access_token) {
    localStorage.setItem("access_token", data.access_token);
    return { success: true, access_token: data.access_token };
  }

  return { success: false };
}

// ---------- Protected: Get Profile ----------
export function getProfile() {
  return authFetch(`${API_BASE}/profile`);
}

// ---------- Logout User ----------
export async function logoutUser() {
  const token = getAccessToken();

  const res = await fetch(`${API_BASE}/logout`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    }
  });

  localStorage.clear();
  return res.ok;
}

// ---------- Collect Log (System Logging) ----------
export async function collectLog(logData) {
  const res = await fetch(`${API_BASE}/collect-log`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(logData)
  });

  return res.json();
}

// ---------- Get Admin Dashboard ----------
export function getAdminDashboard() {
  return authFetch(`${API_BASE}/admin/dashboard`);
}

// ---------- Get All Users (Admin) ----------
export function getAllUsers() {
  return authFetch(`${API_BASE}/admin/users`);
}

// ---------- Update User Role (Admin) ----------
export async function updateUserRole(userId, newRole) {
  const token = getAccessToken();

  const res = await fetch(`${API_BASE}/admin/users/${userId}/role`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify({ new_role: newRole })
  });

  return res.json();
}

// ---------- Search Logs (Admin) ----------
export async function searchLogs(filters = {}) {
  const token = getAccessToken();
  const queryParams = new URLSearchParams();

  if (filters.action) queryParams.append("action", filters.action);
  if (filters.user_id) queryParams.append("user_id", filters.user_id);
  if (filters.ip) queryParams.append("ip", filters.ip);
  if (filters.skip) queryParams.append("skip", filters.skip);
  if (filters.limit) queryParams.append("limit", filters.limit);

  const res = await fetch(`${API_BASE}/logs/search?${queryParams}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  return res.json();
}

// ---------- Get Enhanced Admin Logs ----------
export function getEnhancedAdminLogs(filters = {}) {
  const queryParams = new URLSearchParams();

  if (filters.status) queryParams.append("status", filters.status);
  if (filters.event_type) queryParams.append("event_type", filters.event_type);
  if (filters.skip) queryParams.append("skip", filters.skip);
  if (filters.limit) queryParams.append("limit", filters.limit);

  const queryString = queryParams.toString();
  const url = queryString ? `${API_BASE}/admin/logs/enhanced?${queryString}` : `${API_BASE}/admin/logs/enhanced`;

  return authFetch(url);
}

// ---------- Get User Logs (Admin) ----------
export function getUserLogs(userId) {
  return authFetch(`${API_BASE}/admin/users/${userId}/logs`);
}

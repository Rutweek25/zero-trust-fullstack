import { useEffect, useState } from "react";
import { getEnhancedAdminLogs } from "../../api/api";
import { useNavigate } from "react-router-dom";

export default function AdminLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchLogs();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function fetchLogs() {
    try {
      const data = await getEnhancedAdminLogs({ limit: 200 });

      if (data && !data.detail) {
        setLogs(Array.isArray(data) ? data : []);
      } else if (data?.detail && (data.detail.includes("Admin access") || data.detail.includes("Not authorized"))) {
        navigate("/dashboard");
      }
    } catch (error) {
      console.error("Failed to fetch logs:", error);
    } finally {
      setLoading(false);
    }
  }

  function isSuspiciousLog(log) {
    if (log.status) {
      return log.status.toLowerCase() === "suspicious";
    }
    if (typeof log.risk_score === "number") {
      return log.risk_score >= 5;
    }
    const suspiciousActions = ["usb_detect", "file_open_confidential", "unauthorized_access"];
    return suspiciousActions.includes(log.action?.toLowerCase());
  }

  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: "50px" }}>
        <p style={{ fontSize: 16, color: "#666" }}>⏳ Loading logs...</p>
      </div>
    );
  }

  return (
    <div>
      {/* Action Bar */}
      <div style={{ marginBottom: "20px" }}>
        <button
          onClick={fetchLogs}
          style={{
            background: "#007bff",
            color: "white",
            border: "none",
            padding: "10px 20px",
            borderRadius: 6,
            cursor: "pointer",
            fontSize: 14,
            fontWeight: 500,
            transition: "all 0.3s",
            boxShadow: "0 2px 4px rgba(0,0,0,0.1)"
          }}
          onMouseEnter={(e) => e.target.style.background = "#0056b3"}
          onMouseLeave={(e) => e.target.style.background = "#007bff"}
        >
          🔄 Refresh Logs
        </button>
      </div>

      {/* Logs Table */}
      {logs.length > 0 ? (
        <div style={{
          backgroundColor: "#fff",
          borderRadius: "8px",
          boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
          border: "1px solid #e0e0e0",
          overflowX: "auto"
        }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ backgroundColor: "#f8f9fa", borderBottom: "2px solid #e0e0e0" }}>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>ID</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>User ID</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Event</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Action</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Details</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>IP</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Location</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Device</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Risk</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Timestamp</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, idx) => {
                const isSuspicious = isSuspiciousLog(log);
                return (
                  <tr
                    key={log.id}
                    style={{
                      borderBottom: "1px solid #e0e0e0",
                      backgroundColor: isSuspicious ? "#fff5f5" : (idx % 2 === 0 ? "#fff" : "#f8f9fa"),
                      transition: "background-color 0.2s"
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = isSuspicious ? "#ffe0e0" : "#e8f4f8"}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = isSuspicious ? "#fff5f5" : (idx % 2 === 0 ? "#fff" : "#f8f9fa")}
                  >
                    <td style={{ padding: "12px 16px", color: "#1a1a1a", fontSize: 13 }}>{log.id}</td>
                    <td style={{ padding: "12px 16px", color: "#1a1a1a", fontSize: 13, fontWeight: 500 }}>{log.user_id ?? "-"}</td>
                    <td style={{ padding: "12px 16px", color: "#1a1a1a", fontSize: 12, fontWeight: 600 }}>{log.event_type || "-"}</td>
                    <td style={{ padding: "12px 16px", color: "#1a1a1a", fontSize: 13 }}>
                      <span style={{
                        backgroundColor: isSuspicious ? "#ffebee" : "#e7f3ff",
                        color: isSuspicious ? "#c82333" : "#0056b3",
                        padding: "4px 8px",
                        borderRadius: 4,
                        fontSize: 12,
                        fontWeight: 600
                      }}>
                        {isSuspicious && "⚠️ "}{log.action}
                      </span>
                    </td>
                    <td style={{ padding: "12px 16px", color: "#666", fontSize: 13 }}>{log.details}</td>
                    <td style={{ padding: "12px 16px", color: "#666", fontSize: 13, fontFamily: "monospace" }}>{log.ip || log.ip_address || "-"}</td>
                    <td style={{ padding: "12px 16px", color: "#666", fontSize: 13 }}>{log.location || "-"}</td>
                    <td style={{ padding: "12px 16px", color: "#666", fontSize: 13 }}>{log.device || "-"}</td>
                    <td style={{ padding: "12px 16px", color: isSuspicious ? "#c82333" : "#2e7d32", fontSize: 13, fontWeight: 600 }}>{typeof log.risk_score === "number" ? log.risk_score : "-"}</td>
                    <td style={{ padding: "12px 16px", color: "#666", fontSize: 12 }}>{log.timestamp || log.time || "N/A"}</td>
                    <td style={{ padding: "12px 16px" }}>
                      <span style={{
                        backgroundColor: isSuspicious ? "#ffcdd2" : "#c8e6c9",
                        color: isSuspicious ? "#c82333" : "#2e7d32",
                        padding: "4px 8px",
                        borderRadius: 4,
                        fontSize: 12,
                        fontWeight: 600
                      }}>
                        {isSuspicious ? "🚨 Suspicious" : "✓ Normal"}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{
          backgroundColor: "#fff",
          borderRadius: "8px",
          padding: "40px",
          textAlign: "center",
          border: "1px solid #e0e0e0"
        }}>
          <p style={{ fontSize: 16, color: "#999" }}>📭 No logs found</p>
        </div>
      )}

    </div>
  );
}

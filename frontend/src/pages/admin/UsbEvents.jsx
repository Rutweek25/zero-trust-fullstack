import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getAdminUsbEvents } from "../../api/api";

export default function AdminUsbEvents() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchEvents();
    const timer = setInterval(() => {
      fetchEvents(false);
    }, 2000);

    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function fetchEvents(showLoading = true) {
    if (showLoading) setLoading(true);
    try {
      const data = await getAdminUsbEvents({ limit: 300 });
      if (data && !data.detail) {
        setEvents(Array.isArray(data?.data) ? data.data : []);
      } else if (data?.detail && (data.detail.includes("Admin access") || data.detail.includes("Not authorized"))) {
        navigate("/dashboard");
      }
    } catch (error) {
      console.error("Failed to fetch USB events:", error);
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  function formatTimestamp(value) {
    if (!value) return "N/A";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    return parsed.toLocaleString("en-IN", { hour12: false });
  }

  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: "50px" }}>
        <p style={{ fontSize: 16, color: "#666" }}>⏳ Loading USB events...</p>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: "20px" }}>
        <button
          onClick={fetchEvents}
          style={{
            background: "#007bff",
            color: "white",
            border: "none",
            padding: "10px 20px",
            borderRadius: 6,
            cursor: "pointer",
            fontSize: 14,
            fontWeight: 500,
            boxShadow: "0 2px 4px rgba(0,0,0,0.1)"
          }}
        >
          🔄 Refresh USB Events
        </button>
      </div>

      {events.length > 0 ? (
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
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Device ID</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Hostname</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Event</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Details</th>
                <th style={{ padding: "14px 16px", textAlign: "left", fontWeight: 600, color: "#1a1a1a", fontSize: 13 }}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, idx) => {
                const isInsert = String(event.event || "").toLowerCase().includes("inserted");
                const isRemove = String(event.event || "").toLowerCase().includes("removed");
                return (
                  <tr
                    key={`${event.telemetry_id}-${idx}`}
                    style={{
                      borderBottom: "1px solid #e0e0e0",
                      backgroundColor: idx % 2 === 0 ? "#fff" : "#f8f9fa"
                    }}
                  >
                    <td style={{ padding: "12px 16px", color: "#1a1a1a", fontSize: 13 }}>{event.device_id}</td>
                    <td style={{ padding: "12px 16px", color: "#1a1a1a", fontSize: 13 }}>{event.hostname || "-"}</td>
                    <td style={{ padding: "12px 16px" }}>
                      <span style={{
                        backgroundColor: isInsert ? "#e8f5e9" : isRemove ? "#ffebee" : "#e7f3ff",
                        color: isInsert ? "#2e7d32" : isRemove ? "#c82333" : "#0056b3",
                        padding: "4px 8px",
                        borderRadius: 4,
                        fontSize: 12,
                        fontWeight: 600
                      }}>
                        {event.event || "USB changed"}
                      </span>
                    </td>
                    <td style={{ padding: "12px 16px", color: "#666", fontSize: 13 }}>{event.description || "-"}</td>
                    <td style={{ padding: "12px 16px", color: "#666", fontSize: 12 }}>{formatTimestamp(event.event_timestamp || event.collected_at)}</td>
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
          padding: "24px",
          textAlign: "center",
          border: "1px solid #e0e0e0"
        }}>
          <p style={{ fontSize: 15, color: "#999", margin: 0 }}>No USB events found</p>
        </div>
      )}
    </div>
  );
}
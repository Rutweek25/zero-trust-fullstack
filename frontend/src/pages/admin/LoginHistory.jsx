import { useState, useEffect } from "react";
import { getLoginHistory } from "../../api/api";
import "./LoginHistory.css";

export default function LoginHistory() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState({});
  const [pagination, setPagination] = useState({ page: 1, total_pages: 1 });
  
  // Filters
  const [filters, setFilters] = useState({
    status: "",
    country: "",
    min_risk_score: "",
    page: 1,
    limit: 25
  });
  
  // Selected session for map view
  const [selectedSession, setSelectedSession] = useState(null);

  useEffect(() => {
    fetchHistory();
  }, [filters.page, filters.status, filters.country, filters.min_risk_score]);

  async function fetchHistory() {
    setLoading(true);
    setError("");
    
    try {
      const data = await getLoginHistory(filters);
      
      if (data && data.data) {
        setSessions(data.data);
        setSummary(data.summary || {});
        setPagination(data.pagination || { page: 1, total_pages: 1 });
      } else {
        setError("No data received from server");
      }
    } catch (err) {
      console.error("Error fetching login history:", err);
      setError("Failed to load login history");
    } finally {
      setLoading(false);
    }
  }

  function handleFilterChange(key, value) {
    setFilters(prev => ({ ...prev, [key]: value, page: 1 }));
  }

  function handlePageChange(newPage) {
    setFilters(prev => ({ ...prev, page: newPage }));
  }

  function getRiskBadgeClass(riskScore) {
    if (riskScore >= 0.6) return "risk-badge critical";
    if (riskScore >= 0.3) return "risk-badge suspicious";
    return "risk-badge normal";
  }

  function getStatusBadgeClass(status) {
    if (status === "critical") return "status-badge critical";
    if (status === "suspicious") return "status-badge suspicious";
    return "status-badge normal";
  }

  function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
  }

  function openGoogleMaps(lat, lng) {
    if (lat && lng) {
      window.open(`https://www.google.com/maps?q=${lat},${lng}`, "_blank");
    }
  }

  function parseRiskFactors(riskFactorsJson) {
    try {
      if (!riskFactorsJson) return [];
      return JSON.parse(riskFactorsJson);
    } catch {
      return [];
    }
  }

  return (
    <div className="login-history-container">
      <div className="login-history-header">
        <h2>🌍 Login History & Security Monitoring</h2>
        <p>Comprehensive login tracking with geolocation and risk assessment</p>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="summary-cards">
          <div className="summary-card">
            <div className="summary-value">{summary.total_logins || 0}</div>
            <div className="summary-label">Total Logins</div>
          </div>
          <div className="summary-card suspicious">
            <div className="summary-value">{summary.suspicious_percentage || 0}%</div>
            <div className="summary-label">Suspicious</div>
          </div>
          <div className="summary-card critical">
            <div className="summary-value">{summary.critical_percentage || 0}%</div>
            <div className="summary-label">Critical</div>
          </div>
          <div className="summary-card">
            <div className="summary-value">{summary.filtered_results || 0}</div>
            <div className="summary-label">Filtered Results</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="filters-container">
        <div className="filter-group">
          <label>Status:</label>
          <select 
            value={filters.status} 
            onChange={(e) => handleFilterChange("status", e.target.value)}
          >
            <option value="">All</option>
            <option value="normal">Normal</option>
            <option value="suspicious">Suspicious</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Country:</label>
          <input
            type="text"
            placeholder="e.g., US"
            value={filters.country}
            onChange={(e) => handleFilterChange("country", e.target.value.toUpperCase())}
          />
        </div>

        <div className="filter-group">
          <label>Min Risk Score:</label>
          <input
            type="number"
            min="0"
            max="1"
            step="0.1"
            placeholder="0.0 - 1.0"
            value={filters.min_risk_score}
            onChange={(e) => handleFilterChange("min_risk_score", e.target.value)}
          />
        </div>

        <button className="btn-filter" onClick={() => fetchHistory()}>
          🔍 Apply Filters
        </button>

        <button 
          className="btn-clear" 
          onClick={() => setFilters({ status: "", country: "", min_risk_score: "", page: 1, limit: 25 })}
        >
          ✖ Clear
        </button>
      </div>

      {/* Error Display */}
      {error && <div className="error-message">{error}</div>}

      {/* Loading State */}
      {loading && <div className="loading-spinner">Loading login history...</div>}

      {/* Sessions Table */}
      {!loading && sessions.length > 0 && (
        <>
          <div className="sessions-table-wrapper">
            <table className="sessions-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>User</th>
                  <th>IP Address</th>
                  <th>Location</th>
                  <th>Device</th>
                  <th>Browser</th>
                  <th>Risk Score</th>
                  <th>Login Time</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(session => (
                  <tr 
                    key={session.id} 
                    className={session.status === "suspicious" || session.status === "critical" ? "highlight-row" : ""}
                  >
                    <td>
                      <span className={getStatusBadgeClass(session.status)}>
                        {session.status.toUpperCase()}
                      </span>
                    </td>
                    <td>{session.username || "N/A"}</td>
                    <td className="monospace">{session.ip_address}</td>
                    <td>
                      {session.city}, {session.country}
                      {session.latitude && session.longitude && (
                        <button
                          className="btn-map-small"
                          onClick={() => openGoogleMaps(session.latitude, session.longitude)}
                          title="View on Google Maps"
                        >
                          📍
                        </button>
                      )}
                    </td>
                    <td>{session.device || "Unknown"}</td>
                    <td>{session.browser || "Unknown"}</td>
                    <td>
                      <span className={getRiskBadgeClass(session.risk_score)}>
                        {session.risk_score.toFixed(2)}
                      </span>
                    </td>
                    <td>{formatTimestamp(session.login_at)}</td>
                    <td>
                      <button
                        className="btn-details"
                        onClick={() => setSelectedSession(session)}
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="pagination-controls">
            <button
              disabled={pagination.page <= 1}
              onClick={() => handlePageChange(pagination.page - 1)}
            >
              ← Previous
            </button>
            <span>
              Page {pagination.page} of {pagination.total_pages}
            </span>
            <button
              disabled={pagination.page >= pagination.total_pages}
              onClick={() => handlePageChange(pagination.page + 1)}
            >
              Next →
            </button>
          </div>
        </>
      )}

      {/* No Results */}
      {!loading && sessions.length === 0 && (
        <div className="no-results">
          <p>No login sessions found matching your filters.</p>
        </div>
      )}

      {/* Session Detail Modal */}
      {selectedSession && (
        <div className="modal-overlay" onClick={() => setSelectedSession(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Login Session Details</h3>
              <button className="btn-close" onClick={() => setSelectedSession(null)}>✖</button>
            </div>
            
            <div className="modal-body">
              <div className="detail-section">
                <h4>User Information</h4>
                <p><strong>Username:</strong> {selectedSession.username}</p>
                <p><strong>User ID:</strong> {selectedSession.user_id}</p>
              </div>

              <div className="detail-section">
                <h4>Location & Network</h4>
                <p><strong>IP Address:</strong> {selectedSession.ip_address}</p>
                <p><strong>Country:</strong> {selectedSession.country}</p>
                <p><strong>City:</strong> {selectedSession.city}</p>
                {selectedSession.latitude && selectedSession.longitude && (
                  <>
                    <p><strong>Coordinates:</strong> {selectedSession.latitude.toFixed(6)}, {selectedSession.longitude.toFixed(6)}</p>
                    <iframe
                      className="google-maps-embed"
                      src={`https://www.google.com/maps?q=${selectedSession.latitude},${selectedSession.longitude}&output=embed`}
                      allowFullScreen
                      loading="lazy"
                      title="Session Location"
                    />
                  </>
                )}
              </div>

              <div className="detail-section">
                <h4>Device Information</h4>
                <p><strong>Device:</strong> {selectedSession.device}</p>
                <p><strong>Browser:</strong> {selectedSession.browser}</p>
                <p><strong>OS:</strong> {selectedSession.os}</p>
                <p><strong>User Agent:</strong> <span className="monospace-small">{selectedSession.user_agent}</span></p>
              </div>

              <div className="detail-section">
                <h4>Security Assessment</h4>
                <p>
                  <strong>Risk Score:</strong> 
                  <span className={getRiskBadgeClass(selectedSession.risk_score)}>
                    {selectedSession.risk_score.toFixed(2)}
                  </span>
                </p>
                <p>
                  <strong>Status:</strong> 
                  <span className={getStatusBadgeClass(selectedSession.status)}>
                    {selectedSession.status.toUpperCase()}
                  </span>
                </p>
                {selectedSession.risk_factors && (
                  <div className="risk-factors">
                    <strong>Risk Factors:</strong>
                    <ul>
                      {parseRiskFactors(selectedSession.risk_factors).map((factor, idx) => (
                        <li key={idx}>{factor}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              <div className="detail-section">
                <h4>Session Timing</h4>
                <p><strong>Login Time:</strong> {formatTimestamp(selectedSession.login_at)}</p>
                {selectedSession.logout_at && (
                  <p><strong>Logout Time:</strong> {formatTimestamp(selectedSession.logout_at)}</p>
                )}
                <p><strong>Active:</strong> {selectedSession.is_active ? "✅ Yes" : "❌ No"}</p>
              </div>
            </div>

            <div className="modal-footer">
              {selectedSession.latitude && selectedSession.longitude && (
                <button
                  className="btn-primary"
                  onClick={() => openGoogleMaps(selectedSession.latitude, selectedSession.longitude)}
                >
                  📍 Open in Google Maps
                </button>
              )}
              <button className="btn-secondary" onClick={() => setSelectedSession(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

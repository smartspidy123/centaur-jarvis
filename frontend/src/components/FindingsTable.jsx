import { useState, useEffect } from 'react';
import { fetchFindings } from '../api.js';

const FindingsTable = ({ limit = 50, scanId }) => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');

  useEffect(() => {
    loadFindings();
  }, [severityFilter]);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const params = { limit };
      if (severityFilter) params.severity = severityFilter;
      if (scanId) params.scan_id = scanId;
      const data = await fetchFindings(params);
      setFindings(data);
    } catch (error) {
      console.error('Failed to load findings:', error);
    } finally {
      setLoading(false);
    }
  };

  const severityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'badge-error';
      case 'HIGH': return 'badge-warning';
      case 'MEDIUM': return 'badge-info';
      case 'LOW': return 'badge-success';
      default: return 'badge-neutral';
    }
  };

  return (
    <div className="overflow-x-auto">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold">Findings</h3>
        <select
          className="select select-bordered select-sm"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>
      </div>
      {loading ? (
        <div className="text-center p-8">Loading findings...</div>
      ) : findings.length === 0 ? (
        <div className="text-center p-8">No findings found.</div>
      ) : (
        <table className="table table-zebra">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Type</th>
              <th>Endpoint</th>
              <th>Payload</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {findings.map(finding => (
              <tr key={finding.id}>
                <td>
                  <span className={`badge ${severityColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </td>
                <td>{finding.type}</td>
                <td className="truncate max-w-xs">{finding.endpoint}</td>
                <td className="truncate max-w-xs">{finding.payload || 'N/A'}</td>
                <td>{new Date(finding.timestamp).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default FindingsTable;
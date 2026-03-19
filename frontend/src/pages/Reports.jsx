import { useState, useEffect } from 'react';
import { fetchScans } from '../api.js';

const Reports = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const data = await fetchScans({ limit: 50 });
      setScans(data.filter(s => s.status === 'COMPLETED'));
    } catch (error) {
      console.error('Failed to load scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = (scanId) => {
    // Placeholder: generate report via API
    alert(`Generating report for ${scanId}`);
    // window.open(`/api/scans/${scanId}/report`, '_blank');
  };

  if (loading) return <div className="text-center p-8">Loading reports...</div>;

  return (
    <div className="card bg-base-200 shadow">
      <div className="card-body">
        <h1 className="card-title">Reports</h1>
        <p className="text-base-content/70">Download scan reports in HTML or JSON format.</p>
        <div className="overflow-x-auto mt-4">
          <table className="table table-zebra">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Target</th>
                <th>Completed</th>
                <th>Findings</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.scan_id}>
                  <td className="font-mono text-sm">{scan.scan_id.slice(0, 8)}</td>
                  <td className="truncate max-w-xs">{scan.target}</td>
                  <td>{new Date(scan.end_time).toLocaleDateString()}</td>
                  <td>{scan.summary_stats?.total_findings || 'N/A'}</td>
                  <td>
                    <button
                      className="btn btn-xs btn-primary"
                      onClick={() => downloadReport(scan.scan_id)}
                    >
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Reports;
import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import ScanForm from './ScanForm.jsx';
import FindingsTable from './FindingsTable.jsx';
import Charts from './Charts.jsx';
import LiveFeed from './LiveFeed.jsx';
import ScanProgress from './ScanProgress.jsx';
import { fetchStats, fetchScans, pauseScan, resumeScan, deleteScan } from '../api.js';

const Dashboard = () => {
  const [stats, setStats] = useState({});
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState({});

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [statsData, scansData] = await Promise.all([
        fetchStats(),
        fetchScans({ limit: 5 }),
      ]);
      setStats(statsData);
      setScans(scansData);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePauseScan = async (scanId) => {
    setActionLoading(prev => ({ ...prev, [scanId]: 'pause' }));
    try {
      await pauseScan(scanId);
      await loadData(); // Refresh the data
    } catch (error) {
      console.error('Failed to pause scan:', error);
    } finally {
      setActionLoading(prev => ({ ...prev, [scanId]: null }));
    }
  };

  const handleResumeScan = async (scanId) => {
    setActionLoading(prev => ({ ...prev, [scanId]: 'resume' }));
    try {
      await resumeScan(scanId);
      await loadData(); // Refresh the data
    } catch (error) {
      console.error('Failed to resume scan:', error);
    } finally {
      setActionLoading(prev => ({ ...prev, [scanId]: null }));
    }
  };

  const handleDeleteScan = async (scanId) => {
    if (!window.confirm('Are you sure you want to delete this scan?')) {
      return;
    }
    setActionLoading(prev => ({ ...prev, [scanId]: 'delete' }));
    try {
      await deleteScan(scanId);
      await loadData(); // Refresh the data
    } catch (error) {
      console.error('Failed to delete scan:', error);
    } finally {
      setActionLoading(prev => ({ ...prev, [scanId]: null }));
    }
  };

  if (loading) {
    return <div className="text-center p-8">Loading dashboard...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">Total Scans</h2>
            <p className="text-3xl font-bold">{stats.total_scans || 0}</p>
          </div>
        </div>
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">Critical Findings</h2>
            <p className="text-3xl font-bold text-error">{stats.findings_by_severity?.CRITICAL || 0}</p>
          </div>
        </div>
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">High Findings</h2>
            <p className="text-3xl font-bold text-warning">{stats.findings_by_severity?.HIGH || 0}</p>
          </div>
        </div>
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">Active Scans</h2>
            <p className="text-3xl font-bold text-info">{stats.scans_by_status?.RUNNING || 0}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Charts data={stats} />
        </div>
        <div>
          <ScanForm onScanStarted={loadData} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <div className="card bg-base-200 shadow">
            <div className="card-body">
              <h2 className="card-title">Recent Scans</h2>
              <div className="overflow-x-auto">
                <table className="table table-zebra">
                  <thead>
                    <tr>
                      <th>Scan ID</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map(scan => (
                      <tr key={scan.scan_id}>
                        <td className="font-mono text-sm">{scan.scan_id.slice(0, 8)}</td>
                        <td className="truncate max-w-xs">{scan.target}</td>
                        <td>
                          <span className={`badge ${scan.status === 'COMPLETED' ? 'badge-success' : scan.status === 'RUNNING' ? 'badge-info' : scan.status === 'PAUSED' ? 'badge-warning' : 'badge-warning'}`}>
                            {scan.status}
                          </span>
                        </td>
                        <td>
                          <div className="flex gap-1">
                            <Link to={`/scans/${scan.scan_id}`} className="btn btn-xs btn-ghost">View</Link>
                            {scan.status === 'RUNNING' && (
                              <button
                                onClick={() => handlePauseScan(scan.scan_id)}
                                disabled={actionLoading[scan.scan_id]}
                                className="btn btn-xs btn-warning"
                              >
                                {actionLoading[scan.scan_id] === 'pause' ? '...' : 'Pause'}
                              </button>
                            )}
                            {scan.status === 'PAUSED' && (
                              <button
                                onClick={() => handleResumeScan(scan.scan_id)}
                                disabled={actionLoading[scan.scan_id]}
                                className="btn btn-xs btn-success"
                              >
                                {actionLoading[scan.scan_id] === 'resume' ? '...' : 'Resume'}
                              </button>
                            )}
                            <button
                              onClick={() => handleDeleteScan(scan.scan_id)}
                              disabled={actionLoading[scan.scan_id]}
                              className="btn btn-xs btn-error"
                            >
                              {actionLoading[scan.scan_id] === 'delete' ? '...' : 'Delete'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="card-actions justify-end">
                <Link to="/scans" className="btn btn-sm btn-link">View all scans</Link>
              </div>
            </div>
          </div>
        </div>
        <div>
          <LiveFeed />
        </div>
      </div>

      <div className="card bg-base-200 shadow">
        <div className="card-body">
          <h2 className="card-title">Recent Findings</h2>
          <FindingsTable limit={10} />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
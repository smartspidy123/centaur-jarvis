import { useParams } from 'react-router-dom';
import { useState, useEffect } from 'react';
import ScanProgress from '../components/ScanProgress.jsx';
import FindingsTable from '../components/FindingsTable.jsx';
import { fetchScan } from '../api.js';

const ScanDetails = () => {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScan();
  }, [scanId]);

  const loadScan = async () => {
    try {
      const data = await fetchScan(scanId);
      setScan(data);
    } catch (error) {
      console.error('Failed to load scan:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="text-center p-8">Loading scan details...</div>;
  if (!scan) return <div className="text-center p-8">Scan not found.</div>;

  return (
    <div className="space-y-6">
      <div className="card bg-base-200 shadow">
        <div className="card-body">
          <h1 className="card-title">Scan Details</h1>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p><strong>Scan ID:</strong> <code>{scan.scan_id}</code></p>
              <p><strong>Target:</strong> {scan.target}</p>
              <p><strong>Profile:</strong> {scan.profile}</p>
              <p><strong>Status:</strong> <span className={`badge ${scan.status === 'COMPLETED' ? 'badge-success' : scan.status === 'RUNNING' ? 'badge-info' : 'badge-warning'}`}>{scan.status}</span></p>
            </div>
            <div>
              <p><strong>Start Time:</strong> {new Date(scan.start_time).toLocaleString()}</p>
              <p><strong>End Time:</strong> {scan.end_time ? new Date(scan.end_time).toLocaleString() : 'N/A'}</p>
              <p><strong>Duration:</strong> {scan.end_time ? ((new Date(scan.end_time) - new Date(scan.start_time)) / 1000).toFixed(1) + ' seconds' : 'In progress'}</p>
            </div>
          </div>
        </div>
      </div>

      <ScanProgress scanId={scanId} />

      <div className="card bg-base-200 shadow">
        <div className="card-body">
          <h2 className="card-title">Findings</h2>
          <FindingsTable scanId={scanId} limit={100} />
        </div>
      </div>
    </div>
  );
};

export default ScanDetails;
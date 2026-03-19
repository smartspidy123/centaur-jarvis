import { useState, useEffect } from 'react';
import { fetchScan } from '../api.js';

const ScanProgress = ({ scanId }) => {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const interval = setInterval(() => {
      loadScan();
    }, 2000);
    loadScan();
    return () => clearInterval(interval);
  }, [scanId]);

  const loadScan = async () => {
    try {
      const data = await fetchScan(scanId);
      setScan(data);
    } catch (error) {
      console.error('Failed to load scan progress:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="text-center p-4">Loading progress...</div>;
  if (!scan) return <div className="text-center p-4">Scan not found.</div>;

  const phases = [
    { name: 'Recon', key: 'recon' },
    { name: 'Fuzzing', key: 'fuzzing' },
    { name: 'Sniper', key: 'sniper' },
    { name: 'Reporting', key: 'reporting' },
  ];

  return (
    <div className="card bg-base-200 shadow">
      <div className="card-body">
        <h2 className="card-title">Scan Progress</h2>
        <div className="space-y-4">
          {phases.map(phase => (
            <div key={phase.key}>
              <div className="flex justify-between mb-1">
                <span>{phase.name}</span>
                <span>50%</span> {/* Placeholder */}
              </div>
              <progress className="progress progress-primary w-full" value="50" max="100"></progress>
            </div>
          ))}
        </div>
        <div className="mt-4">
          <p><strong>Status:</strong> <span className="badge badge-info">{scan.status}</span></p>
          <p><strong>Target:</strong> {scan.target}</p>
          <p><strong>Started:</strong> {new Date(scan.start_time).toLocaleString()}</p>
        </div>
      </div>
    </div>
  );
};

export default ScanProgress;
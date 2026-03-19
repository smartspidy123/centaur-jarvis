import { useState } from 'react';
import { startScan } from '../api.js';

const ScanForm = ({ onScanStarted }) => {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState('default');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Target is required');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const scan = await startScan({ target, profile });
      onScanStarted?.();
      setTarget('');
      alert(`Scan started with ID: ${scan.scan_id}`);
    } catch (err) {
      setError(err.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card bg-base-200 shadow">
      <div className="card-body">
        <h2 className="card-title">Start New Scan</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-control">
            <label className="label">
              <span className="label-text">Target URL/Domain</span>
            </label>
            <input
              type="text"
              placeholder="https://example.com"
              className="input input-bordered"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={loading}
            />
          </div>
          <div className="form-control">
            <label className="label">
              <span className="label-text">Profile</span>
            </label>
            <select
              className="select select-bordered"
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              disabled={loading}
            >
              <option value="default">Default</option>
              <option value="full">Full</option>
              <option value="recon">Reconnaissance</option>
              <option value="fuzzing">Fuzzing</option>
              <option value="sniper">Nuclei Sniper</option>
            </select>
          </div>
          {error && (
            <div className="alert alert-error mt-4">
              <span>{error}</span>
            </div>
          )}
          <div className="card-actions justify-end mt-4">
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
            >
              {loading ? (
                <span className="loading loading-spinner"></span>
              ) : (
                'Start Scan'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ScanForm;
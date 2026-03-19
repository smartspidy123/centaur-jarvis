import { Pie, Bar } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { useEffect, useState } from 'react';
import { fetchStats } from '../api.js';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const Charts = ({ data }) => {
  const [stats, setStats] = useState(data);

  useEffect(() => {
    if (!data.total_scans) {
      fetchStats().then(setStats);
    }
  }, [data]);

  const severityData = {
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    datasets: [
      {
        label: 'Findings by Severity',
        data: [
          stats.findings_by_severity?.CRITICAL || 0,
          stats.findings_by_severity?.HIGH || 0,
          stats.findings_by_severity?.MEDIUM || 0,
          stats.findings_by_severity?.LOW || 0,
          stats.findings_by_severity?.INFO || 0,
        ],
        backgroundColor: [
          '#ef4444',
          '#f97316',
          '#3b82f6',
          '#10b981',
          '#6b7280',
        ],
      },
    ],
  };

  const scansData = {
    labels: ['PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'],
    datasets: [
      {
        label: 'Scans by Status',
        data: [
          stats.scans_by_status?.PENDING || 0,
          stats.scans_by_status?.RUNNING || 0,
          stats.scans_by_status?.COMPLETED || 0,
          stats.scans_by_status?.FAILED || 0,
          stats.scans_by_status?.CANCELLED || 0,
        ],
        backgroundColor: '#8b5cf6',
      },
    ],
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="card bg-base-200 shadow">
        <div className="card-body">
          <h2 className="card-title">Findings by Severity</h2>
          <div className="h-64">
            <Pie data={severityData} options={{ maintainAspectRatio: false }} />
          </div>
        </div>
      </div>
      <div className="card bg-base-200 shadow">
        <div className="card-body">
          <h2 className="card-title">Scans by Status</h2>
          <div className="h-64">
            <Bar data={scansData} options={{ maintainAspectRatio: false }} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Charts;
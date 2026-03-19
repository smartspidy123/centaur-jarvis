import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
});

// Health

export const fetchHealth = async () => {
  const response = await api.get('/status/health');
  return response.data;
};

// Stats

export const fetchStats = async () => {
  const response = await api.get('/status/stats');
  return response.data;
};

// Scans

export const fetchScans = async (params = {}) => {
  const response = await api.get('/scans', { params });
  return response.data;
};

export const fetchScan = async (scanId) => {
  const response = await api.get(`/scans/${scanId}`);
  return response.data;
};

export const startScan = async (scanData) => {
  const response = await api.post('/scans', scanData);
  return response.data;
};

export const deleteScan = async (scanId) => {
  await api.delete(`/scans/${scanId}`);
};

export const pauseScan = async (scanId) => {
  const response = await api.patch(`/scans/${scanId}/pause`);
  return response.data;
};

export const resumeScan = async (scanId) => {
  const response = await api.patch(`/scans/${scanId}/resume`);
  return response.data;
};

// Findings

export const fetchFindings = async (params = {}) => {
  const response = await api.get('/results/findings', { params });
  return response.data;
};

export const fetchFindingStats = async () => {
  const response = await api.get('/results/stats');
  return response.data;
};

// Error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export default api;
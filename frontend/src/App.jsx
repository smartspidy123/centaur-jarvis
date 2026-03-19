import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './theme.jsx';
import Dashboard from './pages/Home.jsx';
import ScanDetails from './pages/ScanDetails.jsx';
import Reports from './pages/Reports.jsx';
import Layout from './components/Layout.jsx';

function App() {
  return (
    <ThemeProvider>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans/:scanId" element={<ScanDetails />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
        </Layout>
      </Router>
    </ThemeProvider>
  );
}

export default App;
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Firewall from './pages/Firewall';
import TrafficMonitor from './pages/TrafficMonitor';
import IntrusionDetection from './pages/IntrusionDetection';
import AnomalyDetection from './pages/AnomalyDetection';
import Settings from './pages/Settings';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/firewall" element={<Firewall />} />
        <Route path="/traffic" element={<TrafficMonitor />} />
        <Route path="/detection" element={<IntrusionDetection />} />
        <Route path="/anomaly" element={<AnomalyDetection />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  );
}

export default App;

import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import DemoPage from './pages/DemoPage';
import InteractivePage from './pages/InteractivePage';
import ScenariosPage from './pages/ScenariosPage';
import MitrePage from './pages/MitrePage';

function App() {
  return (
    <Routes>
      {/* Demo mode is full-screen, no layout chrome */}
      <Route path="/" element={<DemoPage />} />

      {/* All other pages use the sidebar layout */}
      <Route element={<Layout />}>
        <Route path="/interactive" element={<InteractivePage />} />
        <Route path="/scenarios" element={<ScenariosPage />} />
        <Route path="/mitre" element={<MitrePage />} />
      </Route>
    </Routes>
  );
}

export default App;

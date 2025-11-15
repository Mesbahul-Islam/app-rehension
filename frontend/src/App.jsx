import { BrowserRouter as Router, Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, History as HistoryIcon, GitCompare, Sparkles, Plus } from 'lucide-react';
import { motion } from 'motion/react';
import { useState } from 'react';
import Home from './pages/Home';
import History from './pages/History';
import Compare from './pages/Compare';

function Navigation({ onReset }) {
  const location = useLocation();
  const navigate = useNavigate();
  
  const isActive = (path) => {
    return location.pathname === path;
  };
  
  const navLinkClass = (path) => {
    const baseClasses = "px-4 py-2 rounded-lg transition-all flex items-center gap-2 group shadow-lg";
    if (isActive(path)) {
      return `${baseClasses} bg-white/30 text-white font-semibold ring-2 ring-white/50`;
    }
    return `${baseClasses} text-purple-100 hover:bg-white/10`;
  };
  
  const handleNewAssessment = () => {
    onReset();
    navigate('/');
  };
  
  return (
    <motion.nav
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.6, duration: 0.5 }}
      className="flex items-center gap-2"
    >
      <Link
        to="/"
        className={navLinkClass("/")}
      >
        <Shield className="w-4 h-4 group-hover:scale-110 transition-transform" />
        Home
      </Link>
      <Link
        to="/history"
        className={navLinkClass("/history")}
      >
        <HistoryIcon className="w-4 h-4 group-hover:scale-110 transition-transform" />
        History
      </Link>
      <Link
        to="/compare"
        className={navLinkClass("/compare")}
      >
        <GitCompare className="w-4 h-4 group-hover:scale-110 transition-transform" />
        Compare
      </Link>
      <button
        onClick={handleNewAssessment}
        className="px-4 py-2 rounded-lg transition-all flex items-center gap-2 group shadow-lg bg-gradient-to-r from-green-500 to-emerald-600 text-white font-semibold hover:from-green-600 hover:to-emerald-700 hover:scale-105 ring-2 ring-green-400/50"
      >
        <Plus className="w-4 h-4 group-hover:rotate-90 transition-transform" />
        New Assessment
      </button>
    </motion.nav>
  );
}

function App() {
  // Lift assessment state to App level so it persists across route changes
  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [sessionId, setSessionId] = useState(null);
  const [showProgress, setShowProgress] = useState(false);

  const handleAssessmentStart = (newSessionId) => {
    setSessionId(newSessionId);
    setShowProgress(true);
    setLoading(true);
    setError(null);
    setAssessment(null);
  };

  const handleAssessmentComplete = (result) => {
    setAssessment(result);
    setLoading(false);
    setShowProgress(false);
  };

  const handleAssessmentError = (err) => {
    setError(err);
    setLoading(false);
    setShowProgress(false);
  };

  const handleReset = () => {
    setAssessment(null);
    setError(null);
    setLoading(false);
    setShowProgress(false);
    setSessionId(null);
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-950 text-gray-100 relative overflow-hidden">
        {/* Animated Background */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-purple-600/20 rounded-full blur-3xl animate-pulse"></div>
          <div
            className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-600/20 rounded-full blur-3xl animate-pulse"
            style={{ animationDelay: "1s" }}
          ></div>
          <div
            className="absolute top-1/2 left-1/2 w-96 h-96 bg-pink-600/10 rounded-full blur-3xl animate-pulse"
            style={{ animationDelay: "2s" }}
          ></div>
        </div>

        {/* Grid Pattern Overlay */}
        <div
          className="fixed inset-0 pointer-events-none opacity-10"
          style={{
            backgroundImage:
              "linear-gradient(rgba(139, 92, 246, 0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(139, 92, 246, 0.3) 1px, transparent 1px)",
            backgroundSize: "50px 50px",
          }}
        ></div>

        {/* Header */}
        <motion.header
          initial={{ y: -100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.6 }}
          className="relative z-10 bg-gradient-to-r from-purple-900/80 via-purple-700/80 to-purple-600/80 border-b border-purple-500/30 backdrop-blur-xl"
        >
          <div className="container mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              {/* Logo and Brand */}
              <motion.div
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: 0.2, duration: 0.5 }}
                className="flex items-center gap-3"
              >
                <div className="relative">
                  <Shield className="w-8 h-8 text-white relative z-10" />
                  <div className="absolute inset-0 bg-purple-400 blur-lg opacity-50 animate-pulse"></div>
                </div>
                <div>
                  <h1 className="text-xl font-bold text-white bg-gradient-to-r from-white to-purple-200 bg-clip-text">
                    App-rehension
                  </h1>
                  <p className="text-xs text-purple-100 flex items-center gap-1">
                    <Sparkles className="w-3 h-3" />
                    Clarity. Control. No more guessing.
                  </p>
                </div>
              </motion.div>

              {/* Navigation */}
              <Navigation onReset={handleReset} />
            </div>
          </div>
        </motion.header>

        {/* Main Content */}
        <main className="relative z-10">
          <Routes>
            <Route 
              path="/" 
              element={
                <Home 
                  assessment={assessment}
                  loading={loading}
                  error={error}
                  sessionId={sessionId}
                  showProgress={showProgress}
                  onAssessmentStart={handleAssessmentStart}
                  onAssessmentComplete={handleAssessmentComplete}
                  onAssessmentError={handleAssessmentError}
                  onReset={handleReset}
                />
              } 
            />
            <Route path="/history" element={<History />} />
            <Route path="/compare" element={<Compare />} />
          </Routes>
        </main>

        {/* Footer */}
        <motion.footer
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 2, duration: 0.6 }}
          className="relative z-10 bg-gray-900/50 backdrop-blur-xl border-t border-gray-800/50 mt-12"
        >
          <div className="container mx-auto px-6 py-8">
            <div className="flex items-center justify-center gap-2 text-gray-500 text-sm">
              <Shield className="w-4 h-4 text-purple-500" />
              <p>
                © 2025 Security Assessor. AI-powered security analysis.
              </p>
              <Sparkles className="w-4 h-4 text-purple-500" />
            </div>
          </div>
        </motion.footer>
      </div>
    </Router>
  );
}

export default App;

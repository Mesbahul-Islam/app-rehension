import { useState, useEffect } from 'react';
import { assessmentAPI } from '../services/api';
import { Link, useNavigate } from 'react-router-dom';

function History() {
  const navigate = useNavigate();
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all'); // all, high-risk, low-risk

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    try {
      setLoading(true);
      const data = await assessmentAPI.getHistory();
      // Backend returns { success: true, assessments: [...] }
      setAssessments(data.assessments || []);
      setError(null);
    } catch (err) {
      console.error('Failed to load history:', err);
      setError(err.message || 'Failed to load assessment history');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (assessmentId) => {
    if (!window.confirm('Are you sure you want to delete this assessment?')) {
      return;
    }

    try {
      await assessmentAPI.deleteAssessment(assessmentId);
      // Remove from local state
      setAssessments(prev => prev.filter(a => a.id !== assessmentId));
    } catch (err) {
      alert('Failed to delete assessment: ' + (err.message || 'Unknown error'));
    }
  };

  const handleView = async (assessmentMeta) => {
    try {
      // Fetch the full assessment data by ID
      const response = await assessmentAPI.getAssessmentById(assessmentMeta.id);
      if (response.success && response.assessment) {
        // Store assessment in sessionStorage and navigate to home
        sessionStorage.setItem('viewAssessment', JSON.stringify(response.assessment));
        navigate('/');
      }
    } catch (err) {
      alert('Failed to load assessment details: ' + (err.message || 'Unknown error'));
    }
  };

  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'low', color: '#43A047', label: 'Low Risk' };
    if (score >= 60) return { level: 'medium', color: '#FBC02D', label: 'Medium Risk' };
    if (score >= 40) return { level: 'high', color: '#FF6F00', label: 'High Risk' };
    return { level: 'critical', color: '#D32F2F', label: 'Critical Risk' };
  };

  const getFilteredAssessments = () => {
    if (filter === 'all') return assessments;
    
    return assessments.filter(assessment => {
      const score = assessment.trust_score || 0;
      if (filter === 'high-risk') return score < 60;
      if (filter === 'low-risk') return score >= 60;
      return true;
    });
  };

  const filteredAssessments = getFilteredAssessments();

  if (loading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="flex flex-col items-center justify-center min-h-[400px]">
          <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4"></div>
          <p className="text-muted-foreground">Loading assessment history...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-4xl font-bold mb-2">Assessment History</h1>
            <p className="text-muted-foreground">
              View and manage your past security assessments
            </p>
          </div>
          <Link 
            to="/" 
            className="inline-flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors font-medium"
          >
            New Assessment
          </Link>
        </div>

        {error && (
          <div className="p-4 bg-destructive/10 border border-destructive/30 rounded-lg text-destructive mb-6">
            {error}
          </div>
        )}

        {!error && (
          <>
            {/* Filters */}
            <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
              <div className="flex gap-2">
                <button
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    filter === 'all'
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
                  }`}
                  onClick={() => setFilter('all')}
                >
                  All ({assessments.length})
                </button>
                <button
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    filter === 'high-risk'
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
                  }`}
                  onClick={() => setFilter('high-risk')}
                >
                  High Risk ({assessments.filter(a => (a.trust_score || 0) < 60).length})
                </button>
                <button
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    filter === 'low-risk'
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
                  }`}
                  onClick={() => setFilter('low-risk')}
                >
                  Low Risk ({assessments.filter(a => (a.trust_score || 0) >= 60).length})
                </button>
              </div>
              <button 
                onClick={loadHistory} 
                className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium"
              >
                Refresh
              </button>
            </div>

            {/* Assessment List */}
            {filteredAssessments.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 bg-card border border-border rounded-xl">
                <div className="w-20 h-20 mb-4 bg-secondary rounded-full flex items-center justify-center">
                  <svg className="w-10 h-10 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold mb-2">No Assessments Found</h3>
                <p className="text-muted-foreground mb-6 text-center max-w-md">
                  {filter !== 'all' 
                    ? 'No assessments match the selected filter.' 
                    : 'Start by running your first security assessment.'}
                </p>
                <Link 
                  to="/" 
                  className="px-6 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors font-medium"
                >
                  Run Your First Assessment
                </Link>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredAssessments.map((assessment) => {
                  const score = assessment.trust_score || 0;
                  const risk = getRiskLevel(score);
                  const productName = assessment.product_name || assessment.vendor || 'Unknown';
                  const vendor = assessment.vendor;
                  const timestamp = new Date(assessment.updated_at || assessment.created_at || Date.now()).toLocaleString();

                  return (
                    <div key={assessment.id} className="bg-card border border-border rounded-xl shadow-lg overflow-hidden hover:shadow-xl transition-shadow">
                      <div className="p-4 border-b border-border">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1 min-w-0">
                            <h3 className="font-bold text-lg truncate">{productName}</h3>
                            {vendor && vendor !== productName && (
                              <span className="inline-block px-2 py-1 bg-secondary text-secondary-foreground rounded text-xs mt-1">
                                {vendor}
                              </span>
                            )}
                          </div>
                          <div 
                            className="shrink-0 px-3 py-1 rounded-full text-xs font-bold ml-2"
                            style={{ 
                              background: `${risk.color}20`,
                              color: risk.color,
                              border: `2px solid ${risk.color}`
                            }}
                          >
                            {risk.label}
                          </div>
                        </div>
                      </div>

                      <div className="p-4">
                        <div className="flex items-center gap-4 mb-4">
                          <div 
                            className="w-20 h-20 rounded-full border-4 flex flex-col items-center justify-center shrink-0"
                            style={{ borderColor: risk.color }}
                          >
                            <span className="text-2xl font-bold" style={{ color: risk.color }}>
                              {score}
                            </span>
                            <span className="text-[10px] text-muted-foreground">Trust</span>
                          </div>
                          <div className="flex-1 text-center">
                            <div className="text-xs text-muted-foreground mb-1">Assessment ID</div>
                            <div className="text-lg font-bold">#{assessment.id}</div>
                          </div>
                        </div>

                        <div className="space-y-2 text-xs text-muted-foreground mb-4">
                          <div className="flex items-center gap-2">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                            </svg>
                            <span>{timestamp}</span>
                          </div>
                          {assessment.url && (
                            <div className="flex items-center gap-2">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                              </svg>
                              <a href={assessment.url} target="_blank" rel="noopener noreferrer" className="hover:underline truncate">
                                {assessment.url.replace(/^https?:\/\//, '').substring(0, 30)}...
                              </a>
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="p-4 border-t border-border flex gap-2">
                        <button 
                          onClick={() => handleView(assessment)}
                          className="flex-1 px-6 py-4 gap-2 bg-violet-600 text-white rounded-lg hover:bg-violet-700 transition-colors font-medium text-lg disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          View Details
                        </button>
                        <button 
                          onClick={() => handleDelete(assessment.id)}
                          className="px-4 py-2 bg-destructive/10 text-destructive rounded-lg hover:bg-destructive/20 transition-colors text-sm font-medium"
                          title="Delete assessment"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default History;

import AssessmentForm from '../components/assessment/AssessmentForm';
import AssessmentDisplay from '../components/assessment/AssessmentDisplay';
import ProgressTracker from '../components/progress/ProgressTracker';

function Home({ 
  assessment, 
  loading, 
  error, 
  sessionId, 
  showProgress, 
  onAssessmentStart, 
  onAssessmentComplete, 
  onAssessmentError, 
  onReset 
}) {
  return (
    <div className="container mx-auto px-4">
      {/* Hero Section */}
      <section className="text-center py-12 mb-8">
        <h1 className="text-4xl font-bold mb-4">
          Security Assessment Tool
        </h1>
        <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
          Comprehensive security analysis for software products and vendors.
          Get instant insights on vulnerabilities, trust scores, and safer alternatives.
        </p>
      </section>

      {/* Assessment Form */}
      {!assessment && !loading && (
        <AssessmentForm
          onStart={onAssessmentStart}
          onComplete={onAssessmentComplete}
          onError={onAssessmentError}
        />
      )}

      {/* Progress Tracker */}
      {showProgress && sessionId && (
        <ProgressTracker
          sessionId={sessionId}
          onComplete={onAssessmentComplete}
          onError={onAssessmentError}
        />
      )}

      {/* Error Display */}
      {error && (
        <div className="flex justify-center items-center py-12">
          <div className="bg-destructive/10 border border-destructive/30 rounded-xl p-8 max-w-md text-center">
            <h3 className="text-xl font-bold mb-2 text-destructive">Assessment Error</h3>
            <p className="text-muted-foreground mb-6">{error.message || 'An error occurred during assessment'}</p>
            <button 
              onClick={onReset} 
              className="inline-flex items-center justify-center px-6 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors font-medium"
            >
              Try Again
            </button>
          </div>
        </div>
      )}

      {/* Assessment Results */}
      {assessment && !loading && (
        <>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold">Assessment Results</h2>
          </div>
          <AssessmentDisplay assessment={assessment} />
        </>
      )}

      {/* Info Cards */}
      {!assessment && !loading && (
        <section className="mb-12">
          <h2 className="text-2xl font-bold mb-6 text-center">What We Analyze</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-card border border-border rounded-xl p-6 text-center hover:shadow-lg transition-shadow">
              <div className="w-12 h-12 mx-auto mb-3 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <h3 className="font-bold mb-2">Vulnerability Analysis</h3>
              <p className="text-sm text-muted-foreground">Recent CVEs, CVSS scores, and exploited vulnerabilities from CISA KEV</p>
            </div>
            <div className="bg-card border border-border rounded-xl p-6 text-center hover:shadow-lg transition-shadow">
              <div className="w-12 h-12 mx-auto mb-3 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <h3 className="font-bold mb-2">Trust Scoring</h3>
              <p className="text-sm text-muted-foreground">Multi-factor trust assessment based on security posture and vendor reputation</p>
            </div>
            <div className="bg-card border border-border rounded-xl p-6 text-center hover:shadow-lg transition-shadow">
              <div className="w-12 h-12 mx-auto mb-3 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </div>
              <h3 className="font-bold mb-2">Alternatives</h3>
              <p className="text-sm text-muted-foreground">Discover safer alternative products with better security ratings</p>
            </div>
            <div className="bg-card border border-border rounded-xl p-6 text-center hover:shadow-lg transition-shadow">
              <div className="w-12 h-12 mx-auto mb-3 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
                </svg>
              </div>
              <h3 className="font-bold mb-2">Ecosystem Graph</h3>
              <p className="text-sm text-muted-foreground">Interactive visualization of security relationships and dependencies</p>
            </div>
          </div>
        </section>
      )}

      {/* Supported Input Types */}
      {!assessment && !loading && (
        <section className="mb-12">
          <h2 className="text-2xl font-bold mb-6 text-center">Supported Input Types</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-accent/50 border border-border rounded-lg p-4 flex flex-col items-center text-center">
              <div className="w-10 h-10 mb-2 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                </svg>
              </div>
              <strong className="mb-1">Product Name</strong>
              <span className="text-xs text-muted-foreground">e.g., "Google Chrome"</span>
            </div>
            <div className="bg-accent/50 border border-border rounded-lg p-4 flex flex-col items-center text-center">
              <div className="w-10 h-10 mb-2 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                </svg>
              </div>
              <strong className="mb-1">Vendor Name</strong>
              <span className="text-xs text-muted-foreground">e.g., "Microsoft"</span>
            </div>
            <div className="bg-accent/50 border border-border rounded-lg p-4 flex flex-col items-center text-center">
              <div className="w-10 h-10 mb-2 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
              </div>
              <strong className="mb-1">URL</strong>
              <span className="text-xs text-muted-foreground">e.g., "https://example.com"</span>
            </div>
            <div className="bg-accent/50 border border-border rounded-lg p-4 flex flex-col items-center text-center">
              <div className="w-10 h-10 mb-2 bg-primary/10 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <strong className="mb-1">SHA1 Hash</strong>
              <span className="text-xs text-muted-foreground">e.g., "a1b2c3d4..."</span>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}

export default Home;


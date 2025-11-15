import { useState } from 'react';
import { assessmentAPI } from '../services/api';

function Compare() {
  const [product1, setProduct1] = useState('');
  const [product2, setProduct2] = useState('');
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleCompare = async (e) => {
    e.preventDefault();

    if (!product1.trim() || !product2.trim()) {
      setError('Please enter both product names');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const result = await assessmentAPI.compareProducts(product1.trim(), product2.trim());
      setComparison(result);
    } catch (err) {
      console.error('Comparison error:', err);
      setError(err.message || 'Failed to compare products');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setComparison(null);
    setError(null);
    setProduct1('');
    setProduct2('');
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-2">Compare Products</h1>
          <p className="text-muted-foreground">
            Compare security posture of two products side-by-side
          </p>
        </div>

        {/* Comparison Form */}
        {!comparison && (
          <div className="bg-card border border-border rounded-2xl p-8 shadow-lg">
            <form onSubmit={handleCompare} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
                <div className="space-y-2">
                  <label htmlFor="product1" className="block text-sm font-medium">
                    First Product
                  </label>
                  <input
                    type="text"
                    id="product1"
                    className="w-full px-4 py-3 bg-input-background border border-input rounded-lg focus:outline-none focus:ring-2 focus:ring-ring"
                    value={product1}
                    onChange={(e) => setProduct1(e.target.value)}
                    placeholder="e.g., Google Chrome"
                    disabled={loading}
                  />
                </div>

                <div className="flex items-center justify-center">
                  <span className="text-2xl font-bold text-muted-foreground">VS</span>
                </div>

                <div className="space-y-2">
                  <label htmlFor="product2" className="block text-sm font-medium">
                    Second Product
                  </label>
                  <input
                    type="text"
                    id="product2"
                    className="w-full px-4 py-3 bg-input-background border border-input rounded-lg focus:outline-none focus:ring-2 focus:ring-ring"
                    value={product2}
                    onChange={(e) => setProduct2(e.target.value)}
                    placeholder="e.g., Mozilla Firefox"
                    disabled={loading}
                  />
                </div>
              </div>

              <button
                type="submit"
                className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors font-medium text-lg disabled:opacity-50 disabled:cursor-not-allowed"
                disabled={loading || !product1.trim() || !product2.trim()}
              >
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-primary-foreground/30 border-t-primary-foreground"></div>
                    Comparing...
                  </>
                ) : (
                  'Compare Products'
                )}
              </button>
            </form>

            {error && (
              <div className="mt-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg text-destructive">
                {error}
              </div>
            )}

            {/* Example Comparisons */}
            <div className="mt-8 pt-6 border-t border-border">
              <h4 className="text-sm font-semibold text-muted-foreground mb-4">Popular Comparisons:</h4>
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={() => {
                    setProduct1('Google Chrome');
                    setProduct2('Mozilla Firefox');
                  }}
                  className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium disabled:opacity-50"
                  disabled={loading}
                >
                  Chrome vs Firefox
                </button>
                <button
                  onClick={() => {
                    setProduct1('Apache HTTP Server');
                    setProduct2('nginx');
                  }}
                  className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium disabled:opacity-50"
                  disabled={loading}
                >
                  Apache vs Nginx
                </button>
                <button
                  onClick={() => {
                    setProduct1('Microsoft Windows');
                    setProduct2('Ubuntu Linux');
                  }}
                  className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium disabled:opacity-50"
                  disabled={loading}
                >
                  Windows vs Linux
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Comparison Results */}
        {comparison && (
          <>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-3xl font-bold">Comparison Results</h2>
              <button 
                onClick={handleReset} 
                className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors font-medium"
              >
                New Comparison
              </button>
            </div>

            <ComparisonDisplay comparison={comparison} />
          </>
        )}
      </div>
    </div>
  );
}

function ComparisonDisplay({ comparison }) {
  const product1 = comparison.product1;
  const product2 = comparison.product2;
  const winner = comparison.recommendation;

  const getScoreColor = (score) => {
    if (score >= 80) return '#43A047';
    if (score >= 60) return '#FBC02D';
    if (score >= 40) return '#FF6F00';
    return '#D32F2F';
  };

  return (
    <div className="space-y-6">
      {/* Winner Banner */}
      {winner && (
        <div className="bg-linear-to-r from-yellow-50 to-yellow-100 border-2 border-yellow-400 rounded-xl p-6 flex items-start gap-4">
          <div className="shrink-0 w-12 h-12 bg-yellow-400 text-white rounded-full flex items-center justify-center text-2xl font-bold">
            ★
          </div>
          <div>
            <h3 className="text-xl font-bold text-foreground mb-1">
              Recommendation: {winner.product}
            </h3>
            <p className="text-muted-foreground">{winner.reason}</p>
          </div>
        </div>
      )}

      {/* Side-by-Side Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Product 1 */}
        <div className="bg-card border border-border rounded-xl p-6 shadow-lg">
          <div className="mb-6">
            <h3 className="text-2xl font-bold mb-2">
              {product1.entity?.product_name || product1.entity?.vendor}
            </h3>
            {product1.entity?.vendor && (
              <span className="inline-block px-3 py-1 bg-secondary text-secondary-foreground rounded-full text-sm">
                {product1.entity.vendor}
              </span>
            )}
          </div>

          <div className="flex justify-center mb-6">
            <div 
              className="w-32 h-32 rounded-full border-8 flex flex-col items-center justify-center"
              style={{ borderColor: getScoreColor(product1.trust_score?.total_score || 0) }}
            >
              <span 
                className="text-4xl font-bold"
                style={{ color: getScoreColor(product1.trust_score?.total_score || 0) }}
              >
                {product1.trust_score?.total_score || 0}
              </span>
              <span className="text-xs text-muted-foreground">Trust Score</span>
            </div>
          </div>

          <div className="space-y-3">
            <MetricItem 
              label="Total CVEs"
              value={product1.security_posture?.total_cves || 0}
            />
            <MetricItem 
              label="Critical CVEs"
              value={product1.security_posture?.critical_cves || 0}
              warning={true}
            />
            <MetricItem 
              label="KEV (Exploited)"
              value={product1.security_posture?.kev_count || 0}
              warning={true}
            />
            <MetricItem 
              label="Risk Level"
              value={product1.classification?.risk_level || 'Unknown'}
            />
          </div>
        </div>

        {/* Divider */}
        <div className="hidden lg:flex flex-col items-center justify-center">
          <div className="h-full w-px bg-border"></div>
          <span className="absolute px-4 py-2 bg-background text-2xl font-bold text-muted-foreground">
            VS
          </span>
        </div>

        {/* Product 2 */}
        <div className="bg-card border border-border rounded-xl p-6 shadow-lg">
          <div className="mb-6">
            <h3 className="text-2xl font-bold mb-2">
              {product2.entity?.product_name || product2.entity?.vendor}
            </h3>
            {product2.entity?.vendor && (
              <span className="inline-block px-3 py-1 bg-secondary text-secondary-foreground rounded-full text-sm">
                {product2.entity.vendor}
              </span>
            )}
          </div>

          <div className="flex justify-center mb-6">
            <div 
              className="w-32 h-32 rounded-full border-8 flex flex-col items-center justify-center"
              style={{ borderColor: getScoreColor(product2.trust_score?.total_score || 0) }}
            >
              <span 
                className="text-4xl font-bold"
                style={{ color: getScoreColor(product2.trust_score?.total_score || 0) }}
              >
                {product2.trust_score?.total_score || 0}
              </span>
              <span className="text-xs text-muted-foreground">Trust Score</span>
            </div>
          </div>

          <div className="space-y-3">
            <MetricItem 
              label="Total CVEs"
              value={product2.security_posture?.total_cves || 0}
            />
            <MetricItem 
              label="Critical CVEs"
              value={product2.security_posture?.critical_cves || 0}
              warning={true}
            />
            <MetricItem 
              label="KEV (Exploited)"
              value={product2.security_posture?.kev_count || 0}
              warning={true}
            />
            <MetricItem 
              label="Risk Level"
              value={product2.classification?.risk_level || 'Unknown'}
            />
          </div>
        </div>
      </div>

      {/* Detailed Comparison Table */}
      {comparison.comparison_metrics && (
        <div className="bg-card border border-border rounded-xl p-6 shadow-lg">
          <h3 className="text-xl font-bold mb-4">Detailed Metrics Comparison</h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 font-semibold">Metric</th>
                  <th className="text-left py-3 px-4 font-semibold">
                    {product1.entity?.product_name || 'Product 1'}
                  </th>
                  <th className="text-left py-3 px-4 font-semibold">
                    {product2.entity?.product_name || 'Product 2'}
                  </th>
                  <th className="text-left py-3 px-4 font-semibold">Difference</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(comparison.comparison_metrics).map(([key, values]) => (
                  <tr key={key} className="border-b border-border hover:bg-secondary/20 transition-colors">
                    <td className="py-3 px-4 font-medium">{formatMetricName(key)}</td>
                    <td className="py-3 px-4">{values.product1}</td>
                    <td className="py-3 px-4">{values.product2}</td>
                    <td className={`py-3 px-4 font-semibold ${
                      values.difference > 0 ? 'text-green-600' : 
                      values.difference < 0 ? 'text-red-600' : 'text-muted-foreground'
                    }`}>
                      {values.difference > 0 ? '+' : ''}{values.difference}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function MetricItem({ label, value, warning }) {
  return (
    <div className={`flex items-center justify-between p-3 rounded-lg ${
      warning && value > 0 ? 'bg-red-50 border border-red-200' : 'bg-secondary/30'
    }`}>
      <span className="text-sm font-medium text-foreground">{label}</span>
      <span className={`text-lg font-bold ${
        warning && value > 0 ? 'text-red-600' : 'text-foreground'
      }`}>
        {value}
      </span>
    </div>
  );
}

function formatMetricName(key) {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

export default Compare;

import { useMemo } from 'react';

function TrustScoreVisualization({ trustScore, score, security, entity, embedded = false }) {
  const getScoreColor = () => {
    if (score >= 80) return '#43A047';
    if (score >= 60) return '#FBC02D';
    if (score >= 40) return '#FF6F00';
    return '#D32F2F';
  };

  const getScoreLabel = () => {
    if (score >= 80) return 'Excellent';
    if (score >= 60) return 'Good';
    if (score >= 40) return 'Fair';
    return 'Poor';
  };

  const breakdown = trustScore?.scoring_breakdown || {};
  const weights = trustScore?.weights || { cvss: 50, epss: 40, kev: 10 };

  // Process CVE timeline data from API
  const { chartData, maxCount, yAxisLabels } = useMemo(() => {
    // Get the pre-aggregated timeline from the API
    const timeline = security?.vulnerability_summary?.cve_timeline || {};
    const cves = security?.recent_cves || [];
    
    if (Object.keys(timeline).length === 0) {
      return { chartData: [], maxCount: 0, yAxisLabels: [] };
    }

    // Create severity map from recent CVEs for visualization
    const severityByYear = {};
    cves.forEach(cve => {
      if (cve.published_date) {
        const year = cve.published_date.substring(0, 4);
        if (!severityByYear[year]) {
          severityByYear[year] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        }
        const severity = cve.severity || 'LOW';
        severityByYear[year][severity] = (severityByYear[year][severity] || 0) + 1;
      }
    });

    // Convert timeline to chart data
    const sortedYears = Object.keys(timeline).sort();
    const data = sortedYears.map(year => ({
      date: year,
      count: timeline[year],
      severity: severityByYear[year] || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    }));

    const max = Math.max(...data.map(d => d.count), 1);
    
    // Create nice y-axis labels
    const step = Math.ceil(max / 4);
    const labels = [0, step, step * 2, step * 3, max];

    return { chartData: data, maxCount: max, yAxisLabels: labels };
  }, [security]);

  // Format date for display (year only from API timeline)
  const formatDate = (dateStr) => {
    // Timeline from API is by year only
    return dateStr;
  };

  return (
    <div className={embedded ? "h-full flex flex-col" : "bg-card border border-border rounded-2xl p-4 shadow-lg h-full flex flex-col"}>
      <div className="flex items-center mb-3">
        <h3 className="text-lg font-bold text-foreground">CVE Timeline & Trust Score</h3>
      </div>

      {/* CVE Timeline Graph */}
      <div className="flex-1 flex flex-col">
        {chartData.length > 0 ? (
          <div className="flex-1 flex gap-2">
            {/* Y-axis labels */}
            <div className="flex flex-col justify-between text-xs text-muted-foreground py-2">
              {yAxisLabels.slice().reverse().map((label, idx) => (
                <div key={idx} className="h-0 flex items-center">
                  {label}
                </div>
              ))}
            </div>

            {/* Graph area */}
            <div className="flex-1 flex flex-col justify-center">
              <div className="relative border-l-2 border-b-2 border-border h-[220px]">
                {/* Grid lines */}
                <div className="absolute inset-0 flex flex-col justify-between">
                  {yAxisLabels.map((_, idx) => (
                    <div key={idx} className="border-t border-border/50"></div>
                  ))}
                </div>

                {/* Line graph */}
                <svg 
                  className="absolute inset-0 w-full h-full" 
                  viewBox="0 0 100 100" 
                  preserveAspectRatio="none"
                  style={{ overflow: 'visible' }}
                >
                  {/* Draw line */}
                  <polyline
                    points={chartData.map((d, i) => {
                      const x = (i / Math.max(chartData.length - 1, 1)) * 100;
                      const y = 100 - (d.count / maxCount) * 100;
                      return `${x},${y}`;
                    }).join(' ')}
                    fill="none"
                    stroke={getScoreColor()}
                    strokeWidth="0.5"
                    vectorEffect="non-scaling-stroke"
                  />
                  
                  {/* Draw points */}
                  {chartData.map((d, i) => {
                    const x = (i / Math.max(chartData.length - 1, 1)) * 100;
                    const y = 100 - (d.count / maxCount) * 100;
                    
                    // Determine point color based on severity
                    let pointColor = '#9E9E9E';
                    if (d.severity.CRITICAL > 0) pointColor = '#D32F2F';
                    else if (d.severity.HIGH > 0) pointColor = '#FF6F00';
                    else if (d.severity.MEDIUM > 0) pointColor = '#FBC02D';
                    
                    return (
                      <g key={i}>
                        <circle
                          cx={x}
                          cy={y}
                          r="1"
                          fill={pointColor}
                          stroke="white"
                          strokeWidth="0.3"
                          className="cursor-pointer"
                          vectorEffect="non-scaling-stroke"
                        >
                          <title>{`Year ${d.date}: ${d.count} CVEs\nCritical: ${d.severity.CRITICAL}, High: ${d.severity.HIGH}, Medium: ${d.severity.MEDIUM}, Low: ${d.severity.LOW}`}</title>
                        </circle>
                      </g>
                    );
                  })}
                </svg>
              </div>

              {/* X-axis labels */}
              <div className="flex justify-between text-md text-muted-foreground mt-2 px-1">
                {chartData.length > 0 && (
                  <>
                    <span>{formatDate(chartData[0].date)}</span>
                    {chartData.length > 2 && (
                      <span className="hidden md:inline">
                        {formatDate(chartData[Math.floor(chartData.length / 2)].date)}
                      </span>
                    )}
                    <span>{formatDate(chartData[chartData.length - 1].date)}</span>
                  </>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            <p className="text-sm">No CVE timeline data available</p>
          </div>
        )}

        {/* Legend - only show if not embedded */}
        {!embedded && (
        <div className="mt-3 flex flex-wrap gap-2 text-md">
          <div className="flex items-center gap-1">
            <div className="w-2.5 h-2.5 rounded-full bg-red-600"></div>
            <span className="text-muted-foreground">Critical</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2.5 h-2.5 rounded-full bg-orange-600"></div>
            <span className="text-muted-foreground">High</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-600"></div>
            <span className="text-muted-foreground">Medium</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2.5 h-2.5 rounded-full bg-gray-600"></div>
            <span className="text-muted-foreground">Low</span>
          </div>
        </div>
        )}
      </div>

      {/* Quick Risk Breakdown - only show if not embedded */}
      {!embedded && (
      <div className="mt-3 pt-3 border-t border-border space-y-1.5">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">CVSS Risk ({weights.cvss}%)</span>
          <span className="font-semibold">{(breakdown.avg_cvss || 0).toFixed(1)}/10</span>
        </div>
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">EPSS Risk ({weights.epss}%)</span>
          <span className="font-semibold">{((breakdown.avg_epss || 0) * 100).toFixed(1)}%</span>
        </div>
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">KEV Count ({weights.kev}%)</span>
          <span className="font-semibold">{breakdown.kev_count || 0}</span>
        </div>
      </div>
      )}
    </div>
  );
}

export function CVETimelineLegend() {
  return (
    <div className="bg-secondary/30 rounded-xl p-2 border border-border">
      <div className="text-base font-bold text-foreground mb-3">CVE Severity Legend</div>
      <div className="flex flex-wrap gap-5 text-sm">
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-red-600"></div>
          <span className="text-muted-foreground">Critical</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-orange-600"></div>
          <span className="text-muted-foreground">High</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-yellow-600"></div>
          <span className="text-muted-foreground">Medium</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-gray-600"></div>
          <span className="text-muted-foreground">Low</span>
        </div>
      </div>
    </div>
  );
}

export default TrustScoreVisualization;


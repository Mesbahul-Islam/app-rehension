import { useState } from 'react';

// Risk Component for compact display
function RiskComponentSection({ title, weight, score, maxScore, color }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">{title} ({weight}%)</span>
        <span className="font-bold" style={{ color }}>{score.toFixed(1)}/{maxScore}</span>
      </div>
      <div className="w-full h-2 bg-secondary rounded-full overflow-hidden">
        <div 
          className="h-full rounded-full transition-all"
          style={{ width: `${(score / maxScore) * 100}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}

export function ScoringBreakdownContent({ trustScore }) {
  const breakdown = trustScore?.scoring_breakdown || {};
  const keyFactors = trustScore?.key_factors || [];
  const weights = trustScore?.weights || { cvss: 50, epss: 40, kev: 10 };

  return (
    <div className="space-y-3">
      {/* Formula Display */}
      <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3 border border-blue-200 dark:border-blue-800">
        <h5 className="text-xs font-semibold text-blue-900 dark:text-blue-100 mb-2">Trust Score Formula</h5>
        <div className="text-sm font-mono text-blue-800 dark:text-blue-200">
          Score = 100 - (CVSS×{weights.cvss}% + EPSS×{weights.epss}% + KEV×{weights.kev}%)
        </div>
        <p className="text-xs text-blue-700 dark:text-blue-300 mt-2">
          Lower risk metrics = Higher trust score
        </p>
      </div>

      <p className="text-xs text-muted-foreground">
        Data-driven risk assessment using CVSS, EPSS, and KEV metrics.
      </p>

      {/* Risk Components */}
      <div className="space-y-2">
        <RiskComponentSection
          title="CVSS Risk"
          weight={weights.cvss || 50}
          score={breakdown.avg_cvss || 0}
          maxScore={10}
          color="#FF6F00"
        />
        <RiskComponentSection
          title="EPSS Risk"
          weight={weights.epss || 40}
          score={(breakdown.avg_epss || 0) * 100}
          maxScore={100}
          color="#43A047"
        />
        <div className="flex items-center justify-between text-sm">
          <span className="font-medium">KEV Count ({weights.kev || 10}%)</span>
          <span className="font-bold text-red-600">{breakdown.kev_count || 0}</span>
        </div>
      </div>

      {/* Key Factors */}
      {keyFactors.length > 0 && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-3 mt-3">
          <h5 className="text-xs font-semibold text-yellow-900 dark:text-yellow-100 mb-2">Key Factors</h5>
          <ul className="space-y-1">
            {keyFactors.slice(0, 3).map((factor, idx) => (
              <li key={idx} className="text-xs text-yellow-800 dark:text-yellow-200">• {factor}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function SecurityPostureContent({ security }) {
  if (!security) return <p className="text-sm text-muted-foreground">No data available</p>;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-secondary/30 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">Total CVEs</div>
          <div className="text-2xl font-bold">{security.total_cves || 0}</div>
        </div>
        <div className="bg-secondary/30 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">KEV Count</div>
          <div className="text-2xl font-bold text-red-600">{security.kev_count || 0}</div>
        </div>
        <div className="bg-secondary/30 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">Critical</div>
          <div className="text-2xl font-bold text-red-600">{security.critical_cves || 0}</div>
        </div>
        <div className="bg-secondary/30 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">High</div>
          <div className="text-2xl font-bold text-orange-600">{security.high_cves || 0}</div>
        </div>
      </div>
      {security.vulnerability_summary?.summary && (
        <p className="text-xs text-muted-foreground leading-relaxed mt-3">
          {security.vulnerability_summary.summary}
        </p>
      )}
    </div>
  );
}

function CompactCVEItem({ cve }) {
  const severityColors = {
    'CRITICAL': '#D32F2F',
    'HIGH': '#FF6F00',
    'MEDIUM': '#FBC02D',
    'LOW': '#607D8B',
    'UNKNOWN': '#9E9E9E'
  };

  const severity = cve.severity || 'UNKNOWN';
  const color = severityColors[severity];

  return (
    <div className="bg-secondary/30 rounded-lg p-2 border border-border">
      <div className="flex items-center justify-between">
        <a 
          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary hover:underline font-semibold text-sm"
        >
          {cve.cve_id}
        </a>
        <span 
          className="px-2 py-0.5 rounded-full text-xs font-bold"
          style={{ background: `${color}20`, color: color }}
        >
          {severity}
        </span>
      </div>
    </div>
  );
}

export function VulnerabilitiesContent({ security }) {
  if (!security?.recent_cves || security.recent_cves.length === 0) {
    return <p className="text-sm text-muted-foreground">No vulnerabilities found</p>;
  }

  const [showAll, setShowAll] = useState(false);
  const displayCVEs = showAll ? security.recent_cves : security.recent_cves.slice(0, 5);

  return (
    <div className="space-y-2">
      {displayCVEs.map((cve, index) => (
        <CompactCVEItem key={cve.cve_id || index} cve={cve} />
      ))}
      {security.recent_cves.length > 5 && (
        <button 
          onClick={() => setShowAll(!showAll)}
          className="w-full px-3 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-xs font-medium"
        >
          {showAll ? 'Show Less' : `Show All ${security.recent_cves.length} CVEs`}
        </button>
      )}
    </div>
  );
}

export function SecurityPracticesContent({ practices }) {
  if (!practices || practices.not_applicable) return null;

  const isLLMGenerated = practices.data_source === 'llm_generated';

  return (
    <div className="space-y-3">
      {isLLMGenerated && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-2 border-yellow-500 rounded p-2">
          <p className="text-xs text-yellow-800 dark:text-yellow-200">
            ⚠️ AI-generated. Verify independently.
          </p>
        </div>
      )}
      
      {practices.rating && (
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">Rating:</span>
          <span className={`px-3 py-1 rounded-lg text-xs font-bold ${
            practices.rating === 'excellent' ? 'bg-green-100 text-green-800' :
            practices.rating === 'good' ? 'bg-blue-100 text-blue-800' :
            practices.rating === 'fair' ? 'bg-yellow-100 text-yellow-800' :
            'bg-red-100 text-red-800'
          }`}>
            {practices.rating.toUpperCase()}
          </span>
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>Bug Bounty: {practices.bug_bounty === true ? '✅' : practices.bug_bounty === false ? '❌' : '❓'}</div>
        <div>Disclosure: {practices.disclosure_policy === true ? '✅' : practices.disclosure_policy === false ? '❌' : '❓'}</div>
        <div>Security Team: {practices.security_team_visible === true ? '✅' : practices.security_team_visible === false ? '❌' : '❓'}</div>
        <div>Patches: {practices.patch_cadence || 'Unknown'}</div>
      </div>

      {practices.summary && (
        <p className="text-xs text-muted-foreground leading-relaxed">{practices.summary}</p>
      )}
    </div>
  );
}

export function SecurityIncidentsContent({ incidents }) {
  if (!incidents) return null;

  const isLLMGenerated = incidents.data_source === 'llm_generated';

  return (
    <div className="space-y-3">
      {isLLMGenerated && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-2 border-yellow-500 rounded p-2">
          <p className="text-xs text-yellow-800 dark:text-yellow-200">
            ⚠️ AI-generated. Verify independently.
          </p>
        </div>
      )}

      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="bg-secondary/30 rounded-lg p-2">
          <div className="text-xs text-muted-foreground">Count</div>
          <div className="text-xl font-bold">{incidents.count || 0}</div>
        </div>
        <div className="bg-secondary/30 rounded-lg p-2">
          <div className="text-xs text-muted-foreground">Severity</div>
          <div className="text-sm font-bold uppercase">{incidents.severity || 'None'}</div>
        </div>
        <div className="bg-secondary/30 rounded-lg p-2">
          <div className="text-xs text-muted-foreground">Rating</div>
          <div className="text-sm font-bold uppercase">{incidents.rating || 'Unknown'}</div>
        </div>
      </div>

      {incidents.incidents && incidents.incidents.length > 0 && (
        <div className="space-y-2">
          {incidents.incidents.slice(0, 3).map((incident, idx) => (
            <div key={idx} className="bg-red-50 dark:bg-red-900/20 border-l-2 border-red-500 rounded p-2">
              <p className="text-xs text-red-900 dark:text-red-100">
                {typeof incident === 'string' ? incident : incident.description || 'Unknown incident'}
              </p>
            </div>
          ))}
        </div>
      )}

      {incidents.summary && (
        <p className="text-xs text-muted-foreground leading-relaxed">{incidents.summary}</p>
      )}
    </div>
  );
}

export function DataComplianceContent({ compliance }) {
  if (!compliance) return null;

  if (compliance.not_applicable) {
    return <p className="text-sm text-muted-foreground">{compliance.reason}</p>;
  }

  const isLLMGenerated = compliance.data_source === 'llm_generated';

  return (
    <div className="space-y-3">
      {isLLMGenerated && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-2 border-yellow-500 rounded p-2">
          <p className="text-xs text-yellow-800 dark:text-yellow-200">
            ⚠️ AI-generated. Verify independently.
          </p>
        </div>
      )}

      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">Status:</span>
        <span className={`px-3 py-1 rounded-lg text-xs font-bold ${
          compliance.status === 'compliant' ? 'bg-green-100 text-green-800' :
          compliance.status === 'partial' ? 'bg-yellow-100 text-yellow-800' :
          compliance.status === 'non-compliant' ? 'bg-red-100 text-red-800' :
          'bg-gray-100 text-gray-800'
        }`}>
          {compliance.status ? compliance.status.toUpperCase() : 'UNKNOWN'}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>GDPR: {compliance.gdpr_compliant === true ? '✅' : compliance.gdpr_compliant === false ? '❌' : '❓'}</div>
        <div>Certs: {compliance.certifications?.length || 0}</div>
        <div className="col-span-2">Privacy: {compliance.privacy_rating || 'Unknown'}</div>
      </div>

      {compliance.certifications && compliance.certifications.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {compliance.certifications.slice(0, 3).map((cert, idx) => (
            <span key={idx} className="px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs">
              {cert}
            </span>
          ))}
        </div>
      )}

      {compliance.summary && (
        <p className="text-xs text-muted-foreground leading-relaxed">{compliance.summary}</p>
      )}
    </div>
  );
}

export function AlternativesContent({ alternatives }) {
  return (
    <div className="space-y-2">
      {alternatives.slice(0, 5).map((alt, index) => (
        <div key={index} className="bg-secondary/30 rounded-lg p-3 border border-border">
          <div className="flex justify-between items-start mb-1">
            <h4 className="text-sm font-bold text-foreground">{alt.name || alt.product_name}</h4>
            {alt.trust_score && (
              <span className="px-2 py-0.5 bg-green-100 text-green-800 rounded-full text-xs font-semibold">
                {alt.trust_score}
              </span>
            )}
          </div>
          {alt.rationale && (
            <p className="text-xs text-muted-foreground line-clamp-2">{alt.rationale}</p>
          )}
        </div>
      ))}
    </div>
  );
}

export function MetadataContent({ assessment }) {
  return (
    <div className="space-y-2 text-sm">
      {assessment.timestamp && (
        <div>
          <span className="font-semibold text-muted-foreground">Timestamp:</span>
          <p className="text-foreground">{new Date(assessment.timestamp).toLocaleString()}</p>
        </div>
      )}
      {assessment.assessment_id && (
        <div>
          <span className="font-semibold text-muted-foreground">ID:</span>
          <p className="text-foreground font-mono text-xs">{assessment.assessment_id}</p>
        </div>
      )}
      {assessment.sources && assessment.sources.length > 0 && (
        <div>
          <span className="font-semibold text-muted-foreground">Sources:</span>
          <ul className="list-disc list-inside text-xs mt-1">
            {assessment.sources.map((source, index) => (
              <li key={index}>{source.name} ({source.count || 0})</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

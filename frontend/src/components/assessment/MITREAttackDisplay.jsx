import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldAlert, Target, Network, Link, TrendingUp, 
  AlertTriangle, ChevronDown, ChevronUp, ExternalLink, GitBranch
} from 'lucide-react';
import AttackVectorGraph from './AttackVectorGraph';

/**
 * MITRE ATT&CK Visualization Component
 * Displays attack techniques, tactics, and kill chains mapped from CVEs
 */
export default function MITREAttackDisplay({ mitreData }) {
  const [activeTab, setActiveTab] = useState('graph');
  const [expandedTactic, setExpandedTactic] = useState(null);

  // Debug logging
  console.log('MITREAttackDisplay received data:', {
    hasData: !!mitreData,
    available: mitreData?.available,
    techniqueCount: mitreData?.techniques?.length,
    tacticCount: Object.keys(mitreData?.tactics || {}).length,
    fullData: mitreData
  });

  if (!mitreData?.available) {
    console.log('MITRE ATT&CK display hidden:', { mitreData });
    return null;
  }

  const { techniques = [], tactics = {}, attack_chains = [], attack_matrix = {}, summary = {} } = mitreData;

  // Tab configuration
  const tabs = [
    { id: 'graph', label: 'Attack Graph', icon: GitBranch },
    { id: 'matrix', label: 'ATT&CK Matrix', icon: Target },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="mt-6 bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden"
    >
      {/* Header */}
      <div className="bg-linear-to-r from-red-600 to-orange-600 p-4 text-white">
        <div className="flex items-center gap-3">
          <Target className="w-6 h-6" />
          <div>
            <h2 className="text-xl font-bold">MITRE ATT&CK Framework</h2>
            <p className="text-sm text-red-100">
              Attack techniques and tactics enabled by identified vulnerabilities
            </p>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-gray-50 border-b">
        <StatCard
          label="Total Techniques"
          value={summary.total_techniques || 0}
          icon={<Network className="w-5 h-5 text-blue-600" />}
          color="blue"
        />
        <StatCard
          label="Tactics Covered"
          value={summary.total_tactics || 0}
          icon={<Target className="w-5 h-5 text-purple-600" />}
          color="purple"
        />
        <StatCard
          label="High-Risk Techniques"
          value={summary.high_risk_techniques?.length || 0}
          icon={<AlertTriangle className="w-5 h-5 text-red-600" />}
          color="red"
        />
        <StatCard
          label="Attack Chains"
          value={attack_chains.length}
          icon={<TrendingUp className="w-5 h-5 text-orange-600" />}
          color="orange"
        />
      </div>

      {/* Tabs */}
      <div className="flex border-b overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-6 py-3 font-medium transition-all whitespace-nowrap ${
              activeTab === tab.id
                ? 'text-red-600 border-b-2 border-red-600 bg-red-50'
                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="p-6">
        <AnimatePresence mode="wait">
          {activeTab === 'graph' && (
            <AttackVectorGraph key="graph" mitreData={mitreData} />
          )}
          {activeTab === 'matrix' && (
            <MatrixTab key="matrix" attackMatrix={attack_matrix} />
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

// Overview Tab Component
function OverviewTab({ summary, tactics }) {
  const topTactics = Object.entries(tactics)
    .sort(([, a], [, b]) => b.cve_count - a.cve_count)
    .slice(0, 5);

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="space-y-6"
    >
      {/* Most Common Tactic */}
      {summary.most_common_tactic && (
        <div className="bg-linear-to-r from-red-50 to-orange-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-red-600 shrink-0 mt-1" />
            <div>
              <h3 className="font-semibold text-gray-900 mb-1">
                Primary Attack Vector
              </h3>
              <p className="text-sm text-gray-700">
                Most vulnerabilities enable <span className="font-bold text-red-700">{summary.most_common_tactic}</span> techniques,
                allowing attackers to {getTacticDescription(summary.most_common_tactic)}.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Top Tactics */}
      <div>
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Target className="w-5 h-5 text-red-600" />
          Top Attack Tactics
        </h3>
        <div className="space-y-3">
          {topTactics.map(([tactic, data]) => (
            <div key={tactic} className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-semibold text-gray-900">{tactic}</h4>
                <span className="text-sm font-medium text-red-600">
                  {data.cve_count} CVEs
                </span>
              </div>
              <p className="text-sm text-gray-600 mb-3">
                {getTacticDescription(tactic)}
              </p>
              <div className="flex flex-wrap gap-2">
                {data.techniques.slice(0, 5).map((techId) => (
                  <span
                    key={techId}
                    className="inline-flex items-center px-2 py-1 bg-red-100 text-red-700 text-xs font-medium rounded"
                  >
                    {techId}
                  </span>
                ))}
                {data.techniques.length > 5 && (
                  <span className="text-xs text-gray-500 py-1">
                    +{data.techniques.length - 5} more
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* High-Risk Techniques Alert */}
      {summary.high_risk_techniques && summary.high_risk_techniques.length > 0 && (
        <div className="bg-red-50 border-l-4 border-red-600 p-4 rounded">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-red-900 mb-1">
                High-Risk Techniques ({summary.high_risk_techniques.length})
              </h3>
              <p className="text-sm text-red-800 mb-3">
                These techniques are enabled by multiple vulnerabilities, increasing attack surface:
              </p>
              <div className="space-y-2">
                {summary.high_risk_techniques.slice(0, 3).map((tech) => (
                  <div key={tech.id} className="bg-white rounded p-3 shadow-sm">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-gray-900">
                        {tech.id}: {tech.name}
                      </span>
                      <span className="text-sm text-red-600 font-medium">
                        {tech.related_cves?.length || 0} CVEs
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {tech.tactics?.map((tactic) => (
                        <span
                          key={tactic}
                          className="px-2 py-0.5 bg-red-100 text-red-700 text-xs rounded"
                        >
                          {tactic}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
}

// ATT&CK Matrix Tab
function MatrixTab({ attackMatrix }) {
  const { tactics = [], techniques_by_tactic = {} } = attackMatrix;

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="space-y-4"
    >
      <p className="text-sm text-gray-600 mb-4">
        MITRE ATT&CK Enterprise Matrix showing techniques enabled by vulnerabilities in this product.
        Click technique IDs to view details on MITRE's website.
      </p>

      <div className="overflow-x-auto">
        <div className="inline-grid gap-3" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(180px, 1fr))` }}>
          {/* Tactic Headers */}
          {tactics.map((tactic) => (
            <div key={tactic} className="bg-linear-to-b from-red-600 to-red-700 text-white p-3 rounded-t-lg">
              <h3 className="font-bold text-sm text-center">{tactic}</h3>
            </div>
          ))}

          {/* Technique Cells */}
          {tactics.map((tactic) => (
            <div key={`${tactic}-techniques`} className="bg-white border border-gray-200 rounded-b-lg p-2 space-y-2">
              {techniques_by_tactic[tactic]?.map((tech) => (
                <a
                  key={tech.id}
                  href={tech.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block bg-red-50 hover:bg-red-100 border border-red-200 rounded p-2 transition-colors group"
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-mono text-xs font-bold text-red-700">
                      {tech.id}
                    </span>
                    <ExternalLink className="w-3 h-3 text-red-600 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <p className="text-xs text-gray-700 line-clamp-2">{tech.name}</p>
                  <div className="mt-1">
                    <span className="inline-flex items-center px-1.5 py-0.5 bg-red-200 text-red-800 text-xs font-medium rounded">
                      {tech.cve_count} CVEs
                    </span>
                  </div>
                </a>
              ))}
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// Techniques Tab
function TechniquesTab({ techniques }) {
  const sortedTechniques = [...techniques].sort((a, b) => 
    (b.related_cves?.length || 0) - (a.related_cves?.length || 0)
  );

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="space-y-3"
    >
      <p className="text-sm text-gray-600 mb-4">
        Complete list of MITRE ATT&CK techniques enabled by vulnerabilities. Sorted by number of related CVEs.
      </p>

      {sortedTechniques.map((tech) => (
        <div key={tech.id} className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
          <div className="flex items-start justify-between gap-4 mb-3">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <a
                  href={tech.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono font-bold text-red-600 hover:text-red-800 hover:underline"
                >
                  {tech.id}
                </a>
                <h4 className="font-semibold text-gray-900">{tech.name}</h4>
              </div>
              <p className="text-sm text-gray-600 mb-3">{tech.description}</p>
            </div>
            <div className="shrink-0">
              <span className="inline-flex items-center px-3 py-1 bg-red-100 text-red-700 text-sm font-semibold rounded-full">
                {tech.related_cves?.length || 0} CVEs
              </span>
            </div>
          </div>

          {/* Tactics */}
          <div className="flex flex-wrap gap-2 mb-3">
            {tech.tactics?.map((tactic) => (
              <span
                key={tactic}
                className="inline-flex items-center px-2 py-1 bg-purple-100 text-purple-700 text-xs font-medium rounded"
              >
                {tactic}
              </span>
            ))}
          </div>

          {/* Match Reason */}
          {tech.match_reason && (
            <div className="text-xs text-gray-500 italic">
              Mapping: {tech.match_reason}
            </div>
          )}

          {/* Related CVEs */}
          {tech.related_cves && tech.related_cves.length > 0 && (
            <details className="mt-3">
              <summary className="text-sm text-gray-700 cursor-pointer hover:text-gray-900 font-medium">
                Related CVEs ({tech.related_cves.length})
              </summary>
              <div className="mt-2 flex flex-wrap gap-2">
                {tech.related_cves.map((cve) => (
                  <span
                    key={cve}
                    className="inline-block px-2 py-1 bg-gray-100 text-gray-700 text-xs font-mono rounded"
                  >
                    {cve}
                  </span>
                ))}
              </div>
            </details>
          )}
        </div>
      ))}
    </motion.div>
  );
}

// Kill Chain Tab
function KillChainTab({ attackChains }) {
  if (!attackChains || attackChains.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <TrendingUp className="w-12 h-12 mx-auto mb-3 text-gray-400" />
        <p>No attack chains identified</p>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="space-y-6"
    >
      <p className="text-sm text-gray-600 mb-4">
        Potential attack progression showing how an attacker could chain techniques together across the cyber kill chain.
      </p>

      {attackChains.map((chain, idx) => (
        <div key={idx} className="bg-white border-2 border-red-200 rounded-lg overflow-hidden">
          {/* Chain Header */}
          <div className="bg-linear-to-r from-red-600 to-orange-600 text-white p-4">
            <h3 className="font-bold text-lg mb-1">{chain.name}</h3>
            <p className="text-sm text-red-100">{chain.description}</p>
          </div>

          {/* Kill Chain Steps */}
          <div className="p-4 space-y-4">
            {chain.steps.map((step, stepIdx) => (
              <div key={stepIdx} className="relative">
                {/* Connector Line */}
                {stepIdx < chain.steps.length - 1 && (
                  <div className="absolute left-6 top-16 bottom-0 w-0.5 bg-linear-to-b from-red-400 to-orange-400 -mb-4" />
                )}

                {/* Step Content */}
                <div className="flex items-start gap-4">
                  {/* Step Number */}
                  <div className="shrink-0 w-12 h-12 bg-linear-to-br from-red-600 to-orange-600 text-white rounded-full flex items-center justify-center font-bold text-lg shadow-lg z-10">
                    {stepIdx + 1}
                  </div>

                  {/* Step Details */}
                  <div className="flex-1 bg-gray-50 border border-gray-200 rounded-lg p-4">
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div>
                        <span className="inline-block px-2 py-1 bg-purple-100 text-purple-700 text-xs font-semibold rounded mb-2">
                          {step.tactic}
                        </span>
                        <h4 className="font-semibold text-gray-900">
                          {step.technique_id}: {step.technique_name}
                        </h4>
                      </div>
                      <span className="shrink-0 inline-flex items-center px-2 py-1 bg-red-100 text-red-700 text-xs font-medium rounded">
                        {step.cve_count} CVEs
                      </span>
                    </div>
                    <p className="text-sm text-gray-600">
                      {getStepDescription(step.tactic, step.technique_name)}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </motion.div>
  );
}

// Utility Components
function StatCard({ label, value, icon, color }) {
  const colorClasses = {
    blue: 'bg-blue-50 border-blue-200',
    purple: 'bg-purple-50 border-purple-200',
    red: 'bg-red-50 border-red-200',
    orange: 'bg-orange-50 border-orange-200',
  };

  return (
    <div className={`${colorClasses[color]} border rounded-lg p-3`}>
      <div className="flex items-center justify-between mb-1">
        {icon}
        <span className="text-2xl font-bold text-gray-900">{value}</span>
      </div>
      <p className="text-xs text-gray-600">{label}</p>
    </div>
  );
}

// Helper Functions
function getTacticDescription(tactic) {
  const descriptions = {
    'Initial Access': 'gain initial foothold in your network',
    'Execution': 'run malicious code',
    'Persistence': 'maintain their foothold',
    'Privilege Escalation': 'gain higher-level permissions',
    'Defense Evasion': 'avoid detection',
    'Credential Access': 'steal account credentials',
    'Discovery': 'explore your environment',
    'Lateral Movement': 'move through your network',
    'Collection': 'gather data of interest',
    'Command And Control': 'communicate with compromised systems',
    'Exfiltration': 'steal data',
    'Impact': 'disrupt operations or destroy data',
  };
  return descriptions[tactic] || 'execute attacks';
}

function getStepDescription(tactic, techniqueName) {
  return `Attacker exploits vulnerabilities to execute ${techniqueName}, advancing their attack through the ${tactic} phase of the kill chain.`;
}

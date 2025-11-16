import { useState } from 'react';
import CombinedGraphs from './CombinedGraphs';
import CompactEntityHeader from './CompactEntityHeader';
import ExpandableCard from './ExpandableCard';
import VirusTotalDisplay from './VirusTotalDisplay';
import MITREAttackDisplay from './MITREAttackDisplay';
import {
  ScoringBreakdownContent,
  SecurityPostureContent,
  VulnerabilitiesContent,
  SecurityPracticesContent,
  SecurityIncidentsContent,
  DataComplianceContent,
  AlternativesContent,
  MetadataContent
} from './CardContents';

function AssessmentDisplay({ assessment }) {
  const [openCard, setOpenCard] = useState(null);

  if (!assessment) return null;

  // Debug logging
  console.log('AssessmentDisplay received:', {
    hasVirusTotalData: !!assessment.virustotal_data,
    hasVirusTotal: !!assessment.virustotal,
    hasInputMetadata: !!assessment._input_metadata,
    inputMetadataVtData: !!assessment._input_metadata?.virustotal_data,
    inputMetadataParsedType: assessment._input_metadata?.parsed_type,
    inputType: assessment.input_type,
    assessmentKeys: Object.keys(assessment)
  });

  const entity = assessment.entity;
  const classification = assessment.classification;
  const security = assessment.security_posture;
  const trustScore = assessment.trust_score;
  const alternatives = assessment.alternatives || [];

  const score = trustScore?.total_score || trustScore?.score || 0;

  // Check if this is a SHA1 hash assessment from VirusTotal
  const isVirusTotalAssessment = 
    assessment.virustotal_data || 
    assessment.virustotal ||
    assessment._input_metadata?.virustotal_data ||
    assessment._input_metadata?.parsed_type === 'sha1' ||
    assessment.input_type === 'sha1';

  console.log('isVirusTotalAssessment:', isVirusTotalAssessment);

  // Debug MITRE ATT&CK data
  console.log('Assessment has MITRE ATT&CK:', {
    hasMitreAttack: !!assessment.mitre_attack,
    mitreAvailable: assessment.mitre_attack?.available,
    techniqueCount: assessment.mitre_attack?.techniques?.length,
    keys: Object.keys(assessment)
  });

  // Check if this result is from cache
  const isFromCache = assessment._input_metadata?._from_cache || assessment.metadata?.from_cache;

  const handleCardToggle = (cardKey) => {
    setOpenCard(openCard === cardKey ? null : cardKey);
  };

  // Check if insufficient data was fetched
  const hasInsufficientData = trustScore?.insufficient_data === true || 
                              (security?.total_cves === 0 && trustScore?.score === null);

  // If it's a VirusTotal assessment, show the special VirusTotal layout
  if (isVirusTotalAssessment) {
    return <VirusTotalDisplay assessment={assessment} />;
  }

  return (
    <div className="space-y-4">
      {/* Cache Indicator Badge */}
      {isFromCache && (
        <div className="flex justify-end">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/30 rounded-lg text-green-600 text-sm">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            <span className="font-medium">Loaded from cache</span>
          </div>
        </div>
      )}

      {/* Insufficient Data Warning */}
      {hasInsufficientData && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
          <div className="flex items-start gap-4">
            <div className="shrink-0">
              <svg className="w-6 h-6 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-yellow-500 mb-2">No Data Available</h3>
              <p className="text-muted-foreground mb-3">
                {trustScore?.rationale || "Unable to fetch security data from external APIs. This could mean:"}
              </p>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-2">
                {trustScore?.data_limitations && trustScore.data_limitations.length > 0 ? (
                  trustScore.data_limitations.map((limitation, idx) => (
                    <li key={idx}>{limitation}</li>
                  ))
                ) : (
                  <>
                    <li>The product is very new or not widely analyzed</li>
                    <li>No CVE records exist in the NVD database</li>
                    <li>API services are temporarily unavailable</li>
                    <li>The product name may need to be more specific</li>
                  </>
                )}
              </ul>
              {trustScore?.key_factors && trustScore.key_factors.length > 0 && (
                <div className="mt-3 text-sm text-yellow-600 font-medium">
                  Note: {trustScore.key_factors.join(', ')}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Compact Entity Header */}
      <CompactEntityHeader entity={entity} classification={classification} score={score} />

      {/* Combined Graphs with Legends */}
      <CombinedGraphs 
        assessment={assessment}
        trustScore={trustScore}
        score={score}
        security={security}
        entity={entity}
      />

      {/* Expandable Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Scoring Breakdown */}
        {trustScore && (
          <ExpandableCard 
            key="scoring-breakdown" 
            title="Scoring Breakdown" 
            isOpen={openCard === 'scoring-breakdown'}
            onToggle={() => handleCardToggle('scoring-breakdown')}
          >
            <ScoringBreakdownContent trustScore={trustScore} />
          </ExpandableCard>
        )}

        {/* Security Posture */}
        <ExpandableCard 
          key="security-posture" 
          title="Security Posture" 
          isOpen={openCard === 'security-posture'}
          onToggle={() => handleCardToggle('security-posture')}
        >
          <SecurityPostureContent security={security} />
        </ExpandableCard>

        {/* Vulnerabilities */}
        <ExpandableCard 
          key="vulnerabilities" 
          title="Recent Vulnerabilities (max 200)" 
          badge={security?.total_cves} 
          isOpen={openCard === 'vulnerabilities'}
          onToggle={() => handleCardToggle('vulnerabilities')}
        >
          <VulnerabilitiesContent security={security} />
        </ExpandableCard>

        {/* Security Practices */}
        {assessment.security_practices && (
          <ExpandableCard 
            key="security-practices" 
            title="Security Practices" 
            isOpen={openCard === 'security-practices'}
            onToggle={() => handleCardToggle('security-practices')}
          >
            <SecurityPracticesContent practices={assessment.security_practices} />
          </ExpandableCard>
        )}

        {/* Security Incidents */}
        {assessment.incidents && (
          <ExpandableCard 
            key="security-incidents" 
            title="Security Incidents" 
            badge={assessment.incidents.count} 
            isOpen={openCard === 'security-incidents'}
            onToggle={() => handleCardToggle('security-incidents')}
          >
            <SecurityIncidentsContent incidents={assessment.incidents} />
          </ExpandableCard>
        )}

        {/* Data Compliance */}
        {assessment.data_compliance && (
          <ExpandableCard 
            key="data-compliance" 
            title="Data & Compliance" 
            isOpen={openCard === 'data-compliance'}
            onToggle={() => handleCardToggle('data-compliance')}
          >
            <DataComplianceContent compliance={assessment.data_compliance} />
          </ExpandableCard>
        )}

        {/* Alternatives */}
        {alternatives.length > 0 && (
          <ExpandableCard 
            key="alternatives" 
            title="Alternatives" 
            badge={alternatives.length} 
            isOpen={openCard === 'alternatives'}
            onToggle={() => handleCardToggle('alternatives')}
          >
            <AlternativesContent alternatives={alternatives} />
          </ExpandableCard>
        )}

        {/* Metadata */}
        <ExpandableCard 
          key="metadata" 
          title="ℹMetadata" 
          isOpen={openCard === 'metadata'}
          onToggle={() => handleCardToggle('metadata')}
        >
          <MetadataContent assessment={assessment} />
        </ExpandableCard>
      </div>

      {/* MITRE ATT&CK Framework - Full Width Below Cards */}
      {assessment.mitre_attack && assessment.mitre_attack.available && (
        <MITREAttackDisplay mitreData={assessment.mitre_attack} />
      )}
    </div>
  );
}

export default AssessmentDisplay;

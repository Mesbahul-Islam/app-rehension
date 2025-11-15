import { useState } from 'react';
import CombinedGraphs from './CombinedGraphs';
import CompactEntityHeader from './CompactEntityHeader';
import ExpandableCard from './ExpandableCard';
import VirusTotalDisplay from './VirusTotalDisplay';
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

  const handleCardToggle = (cardKey) => {
    setOpenCard(openCard === cardKey ? null : cardKey);
  };

  // If it's a VirusTotal assessment, show the special VirusTotal layout
  if (isVirusTotalAssessment) {
    return <VirusTotalDisplay assessment={assessment} />;
  }

  return (
    <div className="space-y-4">
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
          title="🛡️ Security Posture" 
          isOpen={openCard === 'security-posture'}
          onToggle={() => handleCardToggle('security-posture')}
        >
          <SecurityPostureContent security={security} />
        </ExpandableCard>

        {/* Vulnerabilities */}
        <ExpandableCard 
          key="vulnerabilities" 
          title="Recent Vulnerabilities" 
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
            title="🔒 Security Practices" 
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
            title="🚨 Security Incidents" 
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
            title="📋 Data & Compliance" 
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
            title="💡 Alternatives" 
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
          title="ℹ️ Metadata" 
          isOpen={openCard === 'metadata'}
          onToggle={() => handleCardToggle('metadata')}
        >
          <MetadataContent assessment={assessment} />
        </ExpandableCard>
      </div>
    </div>
  );
}

export default AssessmentDisplay;

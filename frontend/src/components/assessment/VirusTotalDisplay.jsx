import { Shield, CheckCircle, AlertTriangle, XCircle, FileText, Calendar, ExternalLink } from 'lucide-react';

function VirusTotalDisplay({ assessment }) {
  if (!assessment) return null;

  // Handle both virustotal_data (from _input_metadata) and virustotal (from assessment structure)
  const vtData = assessment.virustotal_data || 
                 assessment._input_metadata?.virustotal_data || 
                 assessment.virustotal;
  
  if (!vtData) return null;

  const entity = assessment.entity;
  const trustScore = assessment.trust_score || {};
  const detectionStats = vtData.detection_stats || vtData.detection?.stats || {};
  const signature = vtData.signature || {};
  
  const malicious = detectionStats.malicious || 0;
  const suspicious = detectionStats.suspicious || 0;
  const undetected = detectionStats.undetected || 0;
  const harmless = detectionStats.harmless || 0;
  const total = malicious + suspicious + undetected + harmless;

  const getStatusColor = () => {
    if (malicious > 0) return 'bg-red-500';
    if (suspicious > 0) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const getStatusText = () => {
    if (malicious > 0) return 'Malicious';
    if (suspicious > 0) return 'Suspicious';
    return 'Clean';
  };

  const getStatusIcon = () => {
    if (malicious > 0) return <XCircle className="w-6 h-6" />;
    if (suspicious > 0) return <AlertTriangle className="w-6 h-6" />;
    return <CheckCircle className="w-6 h-6" />;
  };

  // Get file hash info
  const sha1 = vtData.sha1 || vtData.file_hash?.sha1;
  const fileName = vtData.primary_name || vtData.file_info?.primary_name || entity?.product_name;
  const fileType = vtData.type || vtData.file_info?.type;
  const fileSize = vtData.size || vtData.file_info?.size;
  const lastAnalysisDate = vtData.last_analysis_date || vtData.file_info?.last_analysis_date;
  const detectionRatio = vtData.detection_ratio || vtData.detection?.ratio;
  const sourceUrl = vtData.source_url || vtData.source_url;
  const score = trustScore.total_score || trustScore.score || 0;

  return (
    <div className="space-y-4">
      {/* Header Card */}
      <div className="bg-linear-to-r from-purple-600 to-purple-700 rounded-xl p-6 shadow-md text-white">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-8 h-8" />
          <div>
            <h2 className="text-xl font-bold">VirusTotal Analysis</h2>
            <p className="text-purple-200 text-sm">
              This assessment was generated from a <span className="font-semibold">SHA1 hash lookup</span> using VirusTotal.
            </p>
          </div>
        </div>

        {/* File Information Grid */}
        <div className="grid grid-cols-2 gap-4 bg-purple-800/30 rounded-md p-4">
          {sha1 && (
            <div>
              <span className="text-purple-200 text-sm font-medium">SHA1 Hash:</span>
              <p className="text-white font-mono text-sm break-all">{sha1}</p>
            </div>
          )}
          <div>
            <span className="text-purple-200 text-sm font-medium">File Name:</span>
            <p className="text-white font-medium">{fileName || 'Unknown'}</p>
          </div>
          <div>
            <span className="text-purple-200 text-sm font-medium">File Type:</span>
            <p className="text-white font-medium">{fileType || 'Unknown'}</p>
          </div>
          <div>
            <span className="text-purple-200 text-sm font-medium">File Size:</span>
            <p className="text-white font-medium">{fileSize ? `${(fileSize / (1024 * 1024)).toFixed(2)} MB` : 'Unknown'}</p>
          </div>
          {lastAnalysisDate && (
            <div className="col-span-2">
              <span className="text-purple-200 text-sm font-medium">Last Scanned:</span>
              <p className="text-white font-medium">
                {new Date(lastAnalysisDate).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit'
                })}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Detection Results Card */}
      <div className="bg-card border border-border rounded-xl p-6 shadow-md">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <div>
              <h3 className={`text-xl font-bold ${
                malicious > 0 ? 'text-red-500' : 
                suspicious > 0 ? 'text-yellow-500' : 
                'text-green-500'
              }`}>
                {getStatusText()}
              </h3>
              <p className="text-xl font-bold text-foreground">
                {total} detections
              </p>
            </div>
          </div>
        </div>

        {/* Detection Stats Grid */}
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-red-50 border border-red-200 rounded-md p-4 text-center">
            <p className="text-red-600 font-semibold text-sm mb-1">Malicious</p>
            <p className="text-3xl font-bold text-red-700">{malicious}</p>
          </div>
          <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4 text-center">
            <p className="text-yellow-600 font-semibold text-sm mb-1">Suspicious</p>
            <p className="text-3xl font-bold text-yellow-700">{suspicious}</p>
          </div>
          <div className="bg-gray-50 border border-gray-200 rounded-md p-4 text-center">
            <p className="text-gray-600 font-semibold text-sm mb-1">Undetected</p>
            <p className="text-3xl font-bold text-gray-700">{undetected}</p>
          </div>
          <div className="bg-green-50 border border-green-200 rounded-md p-4 text-center">
            <p className="text-green-600 font-semibold text-sm mb-1">Harmless</p>
            <p className="text-3xl font-bold text-green-700">{harmless}</p>
          </div>
        </div>
      </div>

      {/* Digital Signature Card */}
      {signature && Object.keys(signature).length > 0 && (
        <div className="bg-card border border-border rounded-xl p-6 shadow-md">
          <div className="flex items-center gap-2 mb-4">
            <FileText className="w-5 h-5 text-foreground" />
            <h3 className="text-md font-bold text-foreground">Digital Signature</h3>
          </div>
          
          <div className="space-y-3">
            {signature.verified && (
              <div className="flex items-center gap-2">
                {signature.verified === 'Signed' ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
                <span className="text-sm font-medium text-foreground">
                  Verified: <span className={signature.verified === 'Signed' ? 'text-green-600' : 'text-red-600'}>
                    {signature.verified}
                  </span>
                </span>
              </div>
            )}
            {signature.product && (
              <div>
                <span className="text-sm font-medium text-muted-foreground">Product:</span>
                <p className="text-foreground font-medium">{signature.product}</p>
              </div>
            )}
            {signature.signers && (
              <div>
                <span className="text-sm font-medium text-muted-foreground">Signers:</span>
                <p className="text-foreground text-sm break-all">{signature.signers}</p>
              </div>
            )}
            {signature.copyright && (
              <div>
                <span className="text-sm font-medium text-muted-foreground">Copyright:</span>
                <p className="text-foreground text-sm">{signature.copyright}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* View Full Report Link */}
      {sourceUrl && (
        <div className="bg-card border border-border rounded-xl p-4 shadow-md">
          <a
            href={sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-blue-600 hover:text-blue-700 font-medium"
          >
            <ExternalLink className="w-4 h-4" />
            View full report on VirusTotal
          </a>
        </div>
      )}
    </div>
  );
}

export default VirusTotalDisplay;

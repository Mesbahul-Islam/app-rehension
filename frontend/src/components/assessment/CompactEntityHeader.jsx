function CompactEntityHeader({ entity, classification, score }) {
  const getRiskColorClass = (riskLevel) => {
    const level = riskLevel?.toLowerCase();
    switch(level) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-300';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'low': return 'bg-green-100 text-green-800 border-green-300';
      default: return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const getScoreColor = () => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  return (
    <div className="bg-card border border-border rounded-xl p-4 shadow-lg">
      <div className="flex flex-wrap items-center justify-evenly gap-3">
        <div className="min-w-0">
          <div className="items-center gap-3 mb-1">
            <h2 className="text-lg font-bold text-foreground truncate">
              {entity?.product_name || entity?.vendor || 'Unknown Product'}
            </h2>
            {entity?.vendor && entity.vendor !== entity.product_name && (
              <span className="text-xl text-muted-foreground text-wrap">by {entity.vendor}</span>
            )}
          </div>
          {entity?.description && (
            <p className="text-sm text-muted-foreground line-clamp-2">{entity.description}</p>
          )}
        </div>
        <div className={`flex items-center justify-center w-40 h-20 rounded-full border-4 ${getScoreColor()} border-current`}>
          <span className={`text-2xl font-bold ${getScoreColor()}`}>{score}</span>
          <span className="text-xl font-bold">/ 100</span>
        </div>
        <div className="flex flex-col gap-2">
          {classification?.category && (
            <span className="px-3 py-1 text-2xl font-medium text-white">
              {classification.category}
            </span>
          )}
          {classification?.risk_level && (
            <span className={`px-3 py-1 border rounded-full text-xs font-medium ${getRiskColorClass(classification.risk_level)}`}>
              {classification.risk_level}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

export default CompactEntityHeader;

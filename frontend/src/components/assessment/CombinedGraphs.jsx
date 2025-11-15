import SecurityGraph from '../graph/SecurityGraph';
import TrustScoreVisualization from './TrustScoreVisualization';

function CombinedGraphs({ assessment, trustScore, score, security, entity }) {
  return (
    <div className="bg-card border border-border rounded-2xl p-4 shadow-lg">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 divide-x-0 lg:divide-x divide-border">
        {/* Security Graph */}
        <div className="flex flex-col lg:pr-6">
          <SecurityGraph assessment={assessment} embedded={true} />
          
          {/* Security Graph Legend */}
          <div className="mt-3 pt-3 border-t border-border">
            <div className="text-xs font-bold text-foreground mb-2">Legend</div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-sm">
              <LegendItem color="#1E88E5" border="#1565C0" label="Product" />
              <LegendItem color="#43A047" border="#2E7D32" label="Vendor" />
              <LegendItem color="#D32F2F" border="#B71C1C" label="Critical CVE" />
              <LegendItem color="#FF6F00" border="#E65100" label="High CVE" />
              <LegendItem color="#C2185B" border="#880E4F" label="KEV" />
              <LegendItem color="#8E24AA" border="#6A1B9A" label="Alternative" />
              <LegendItem color="#00897B" border="#00695C" label="Data Source" shape="square" />
            </div>
          </div>
        </div>
        
        {/* Trust Score Visualization */}
        <div className="flex flex-col lg:pl-6">
          <TrustScoreVisualization 
            trustScore={trustScore} 
            score={score} 
            security={security}
            entity={entity}
            embedded={true}
          />
          
          {/* CVE Timeline Legend */}
          <div className="mt-3 pt-3 border-t border-border">
            <div className="text-xs font-bold text-foreground mb-2">CVE Severity</div>
            <div className="flex flex-wrap gap-3 text-[10px]">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-red-600"></div>
                <span className="text-muted-foreground">Critical</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-orange-600"></div>
                <span className="text-muted-foreground">High</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-yellow-600"></div>
                <span className="text-muted-foreground">Medium</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-gray-600"></div>
                <span className="text-muted-foreground">Low</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function LegendItem({ color, border, label, shape = 'circle' }) {
  const shapeStyles = shape === 'square' 
    ? 'w-2 h-2 rounded-sm' 
    : 'w-2 h-2 rounded-full';
  
  return (
    <div className="flex items-center gap-1.5">
      <span
        className={`${shapeStyles} shrink-0`}
        style={{
          background: color,
          border: `2px solid ${border}`,
        }}
      />
      <span className="text-foreground">{label}</span>
    </div>
  );
}

export default CombinedGraphs;

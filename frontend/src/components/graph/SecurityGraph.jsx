import { useEffect, useRef, useState } from 'react';
import { Network } from 'vis-network';

function SecurityGraph({ assessment, embedded = false }) {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const tooltipRef = useRef(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!assessment || !containerRef.current) return;

    // Validate assessment has required structure
    if (!assessment.entity && !assessment.security_posture) {
      console.warn('Assessment missing required data structure for graph rendering');
      setError('Assessment data is incomplete for graph visualization');
      return;
    }

    try {
      // Build graph data
      const { nodes, edges } = buildGraphData(assessment);

      // If no nodes were created, don't try to render the graph
      if (!nodes || nodes.length === 0) {
        console.warn('No graph nodes generated from assessment data');
        setError('Unable to generate graph from assessment data');
        return;
      }

      // Clear any previous errors
      setError(null);

    // Configure graph options
    const options = {
      nodes: {
        shape: 'dot',
        font: {
          size: 16,
          face: 'Arial, sans-serif',
          color: '#333',
          bold: { color: '#000' }
        },
        borderWidth: 3,
        borderWidthSelected: 5,
        shadow: {
          enabled: true,
          color: 'rgba(0,0,0,0.2)',
          size: 8,
          x: 3,
          y: 3
        }
      },
      edges: {
        width: 3,
        color: {
          color: '#666666',
          highlight: '#4a90e2',
          hover: '#4a90e2'
        },
        smooth: {
          enabled: true,
          type: 'continuous',
          roundness: 0.5
        },
        arrows: {
          to: {
            enabled: true,
            scaleFactor: 0.8
          }
        },
        font: {
          size: 16,
          align: 'top',
          color: '#1e293b',
          background: 'rgba(226, 232, 240, 0.85)',
          strokeWidth: 2,
          strokeColor: '#94a3b8'
        }
      },
      physics: {
        enabled: false
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        navigationButtons: true,
        keyboard: true,
        zoomView: true,
        dragView: true,
      },
      layout: {
        hierarchical: {
          enabled: true,
          direction: 'LR',
          sortMethod: 'directed',
          levelSeparation: 300,
          nodeSpacing: 200,
          treeSpacing: 250,
          blockShifting: true,
          edgeMinimization: true,
          parentCentralization: true,
          shakeTowards: 'leaves'
        }
      }
    };

    // Create network
    const data = { nodes, edges };
    networkRef.current = new Network(containerRef.current, data, options);

    // Setup interactions
    setupInteractions(networkRef.current, tooltipRef.current, assessment);

    // Cleanup
    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
    } catch (err) {
      console.error('Error rendering security graph:', err);
      setError(`Failed to render graph: ${err.message}`);
    }
  }, [assessment]);

  // Apply severity filter
  useEffect(() => {
    if (!networkRef.current || !assessment) return;

    try {
      const { nodes, edges } = buildGraphData(assessment);
      
      if (filterSeverity !== 'all') {
        const filteredNodes = nodes.filter(node => {
          if (node.group !== 'cve') return true;
          
          const recentCves = assessment.security_posture?.recent_cves || [];
          const cve = recentCves.find(c => c.cve_id === node.id);
          if (!cve) return false;
          
          if (filterSeverity === 'critical') {
            return cve.severity === 'CRITICAL';
          } else if (filterSeverity === 'high') {
            return cve.severity === 'HIGH';
          } else if (filterSeverity === 'critical_high') {
            return cve.severity === 'CRITICAL' || cve.severity === 'HIGH';
          }
          
          return true;
        });
        
        const nodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredEdges = edges.filter(edge => 
          nodeIds.has(edge.from) && nodeIds.has(edge.to)
        );
        
        networkRef.current.setData({ nodes: filteredNodes, edges: filteredEdges });
      } else {
        networkRef.current.setData({ nodes, edges });
      }
    } catch (err) {
      console.error('Error applying severity filter:', err);
      setError(`Filter error: ${err.message}`);
    }
  }, [filterSeverity, assessment]);

  const handleCenterGraph = () => {
    if (networkRef.current) {
      networkRef.current.focus('product', {
        scale: 1.0,
        animation: {
          duration: 1000,
          easingFunction: 'easeInOutQuad'
        }
      });
    }
  };

  const handleExportPNG = () => {
    if (!containerRef.current) return;
    
    const canvas = containerRef.current.querySelector('canvas');
    if (canvas) {
      const link = document.createElement('a');
      link.download = 'security-ecosystem-graph.png';
      link.href = canvas.toDataURL('image/png');
      link.click();
    }
  };

  const handleTogglePhysics = () => {
    if (!networkRef.current) return;
    const currentPhysics = networkRef.current.physics.options.enabled;
    networkRef.current.setOptions({ physics: { enabled: !currentPhysics } });
  };

  return (
    <div className={embedded ? "" : "bg-card border border-border rounded-2xl p-4 shadow-lg"}>
      <h3 className="text-lg font-bold text-foreground mb-2">
        Security Ecosystem Graph (zoom in to see)
      </h3>
      <p className="text-xs text-muted-foreground mb-4 leading-relaxed">
        Interactive knowledge graph showing relationships between product, vendor, vulnerabilities,
        alternatives, and data sources. Click nodes for details, hover to highlight connections.
      </p>

      {/* Error Display */}
      {error && (
        <div className="p-5 my-5 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <strong className="font-bold">Graph Error:</strong> {error}
        </div>
      )}

      {/* Controls */}
      {!error && (
      <div className="flex flex-nowrap gap-1.5 mb-4 overflow-x-auto">
        <button
          onClick={() => setFilterSeverity('all')}
          className={`px-2 py-1 rounded text-[10px] font-medium transition-colors whitespace-nowrap ${
            filterSeverity === 'all'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          All CVEs
        </button>
        <button
          onClick={() => setFilterSeverity('critical_high')}
          className={`px-2 py-1 rounded text-[10px] font-medium transition-colors whitespace-nowrap ${
            filterSeverity === 'critical_high'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          Critical + High
        </button>
        <button
          onClick={() => setFilterSeverity('critical')}
          className={`px-2 py-1 rounded text-[10px] font-medium transition-colors whitespace-nowrap ${
            filterSeverity === 'critical'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          Critical
        </button>
        <button 
          onClick={handleCenterGraph} 
          className="px-2 py-1 bg-gray-200 text-gray-700 rounded hover:bg-gray-300 transition-colors text-[10px] font-medium whitespace-nowrap"
        >
          Re-center
        </button>
        <button 
          onClick={handleTogglePhysics} 
          className="px-2 py-1 bg-gray-200 text-gray-700 rounded hover:bg-gray-300 transition-colors text-[10px] font-medium whitespace-nowrap"
        >
          Physics
        </button>
        <button 
          onClick={handleExportPNG} 
          className="px-2 py-1 bg-green-600 text-white rounded hover:bg-green-700 transition-colors text-[10px] font-medium whitespace-nowrap"
        >
          Export
        </button>
      </div>
      )}

      {/* Graph Container */}
      {!error && <div ref={containerRef} className="w-full h-[400px] bg-background rounded-lg border border-border mb-4" />}

      {/* Custom Tooltip */}
      {!error && (
        <div 
          ref={tooltipRef} 
          id="graph-custom-tooltip" 
          className="absolute bg-card border-2 border-border rounded-lg p-3 shadow-xl max-w-sm z-50 pointer-events-none"
          style={{ display: 'none' }}
        />
      )}

      {/* Legend - only show if not embedded */}
      {!error && !embedded && <GraphLegend />}
    </div>
  );
}

export function GraphLegend() {
  return (
    <div className="bg-secondary/30 rounded-xl p-4 border border-border">
      <div className="text-sm font-bold text-foreground mb-3">Graph Legend & Guide</div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-4">
        <LegendItem color="#1E88E5" border="#1565C0" label="Product" description="Main item being assessed" />
        <LegendItem color="#43A047" border="#2E7D32" label="Vendor" description="Company/developer" />
        <LegendItem color="#D32F2F" border="#B71C1C" label="Critical CVE" description="Severe vulnerability" />
        <LegendItem color="#FF6F00" border="#E65100" label="High CVE" description="Significant risk" />
        <LegendItem color="#C2185B" border="#880E4F" label="KEV" description="Actively exploited" />
        <LegendItem color="#8E24AA" border="#6A1B9A" label="Alternative" description="Safer option" />
        <LegendItem color="#00897B" border="#00695C" label="Data Source" description="Information provider" shape="square" />
      </div>
    </div>
  );
}

function LegendItem({ color, border, label, description, shape = 'circle' }) {
  const shapeStyles = shape === 'square' 
    ? 'w-5 h-5 rounded-sm' 
    : 'w-5 h-5 rounded-full';
  
  return (
    <div className="flex items-center gap-3">
      <span
        className={`${shapeStyles} shrink-0`}
        style={{
          background: color,
          border: `3px solid ${border}`,
          boxShadow: '0 2px 4px rgba(0,0,0,0.2)'
        }}
      />
      <span className="text-sm">
        <strong className="text-foreground">{label}</strong>
        <span className="text-muted-foreground"> - {description}</span>
      </span>
    </div>
  );
}

// Build graph data from assessment (converted from vanilla JS)
function buildGraphData(assessment) {
  const nodes = [];
  const edges = [];

  // Safety checks for assessment structure
  if (!assessment) {
    console.error('Assessment is undefined');
    return { nodes: [], edges: [] };
  }

  const entity = assessment.entity || {};
  const security = assessment.security_posture || {};
  const alternatives = assessment.alternatives || [];
  const sources = assessment.sources || [];

  // 1. PRODUCT NODE
  const productId = 'product';
  const productName = entity.product_name || entity.vendor || 'Unknown Product';
  const trustScore = assessment.trust_score?.total_score || assessment.trust_score?.score || 'N/A';
  const category = assessment.classification?.category || 'Unknown';
  const riskLevel = assessment.classification?.risk_level || 'Unknown';
  
  nodes.push({
    id: productId,
    label: productName,
    title: `<b>PRIMARY PRODUCT</b><br><br><b>Name:</b> ${productName}<br><b>Trust Score:</b> ${trustScore}/100<br><b>Category:</b> ${category}<br><b>Risk Level:</b> ${riskLevel}<br><br><i>Click to see full details</i>`,
    group: 'product',
    size: 45,
    level: 2,
    color: {
      border: '#1565C0',
      background: '#1E88E5',
      highlight: { border: '#0D47A1', background: '#42A5F5' }
    },
    font: { size: 20, color: '#fff', bold: true },
    mass: 5
  });

  // 2. VENDOR NODE
  if (entity.vendor) {
    const vendorId = 'vendor';
    nodes.push({
      id: vendorId,
      label: entity.vendor,
      title: `<b>VENDOR / MANUFACTURER</b><br><br><b>Company:</b> ${entity.vendor}<br><br><i>The organization that develops and maintains this product</i>`,
      group: 'vendor',
      size: 32,
      level: 0,
      color: {
        border: '#2E7D32',
        background: '#43A047',
        highlight: { border: '#1B5E20', background: '#66BB6A' }
      },
      font: { size: 17, color: '#fff', bold: true },
      mass: 3
    });

    edges.push({
      from: vendorId,
      to: productId,
      label: 'DEVELOPS',
      width: 5,
      color: { color: '#43A047' },
      arrows: { to: { scaleFactor: 1.0 } }
    });
  }

  // 3. CVE NODES
  const recentCVEs = security.recent_cves || [];
  const maxCVEs = 15;

  recentCVEs.slice(0, maxCVEs).forEach((cve) => {
    const cveId = cve.cve_id;
    const severity = cve.severity || 'UNKNOWN';
    const cvssScore = cve.cvss_v3 || 'N/A';

    const severityColors = {
      'CRITICAL': { border: '#B71C1C', background: '#D32F2F', icon: '' },
      'HIGH': { border: '#E65100', background: '#FF6F00', icon: '' },
      'MEDIUM': { border: '#F57F17', background: '#FBC02D', icon: '' },
      'LOW': { border: '#455A64', background: '#607D8B', icon: '' },
      'UNKNOWN': { border: '#424242', background: '#616161', icon: '' }
    };

    const colors = severityColors[severity] || severityColors['UNKNOWN'];

    nodes.push({
      id: cveId,
      label: cveId,
      title: `<b>VULNERABILITY</b><br><br><b>CVE ID:</b> ${cveId}<br><b>Severity:</b> ${severity}<br><b>CVSS Score:</b> ${cvssScore}<br><br>${cve.summary ? '<b>Description:</b><br>' + cve.summary.substring(0, 200) + '...' : ''}<br><br><i>Click to view on NVD database</i>`,
      group: 'cve',
      size: 14 + (severity === 'CRITICAL' ? 8 : severity === 'HIGH' ? 5 : 2),
      level: 3,
      color: {
        border: colors.border,
        background: colors.background,
        highlight: { border: colors.border, background: colors.background }
      },
      font: { size: 11, color: '#fff', bold: true },
      mass: 1
    });

    edges.push({
      from: productId,
      to: cveId,
      label: severity === 'CRITICAL' ? 'CRITICAL VULN' : severity === 'HIGH' ? 'HIGH VULN' : 'HAS VULN',
      width: severity === 'CRITICAL' ? 4 : severity === 'HIGH' ? 3 : 2,
      color: { color: colors.background },
      dashes: false
    });
  });

  // 4. KEV NODES
  const kevList = security.kev_list || [];
  kevList.forEach((kev) => {
    const kevId = `kev_${kev.cve_id}`;

    nodes.push({
      id: kevId,
      label: kev.cve_id,
      title: `<b>ACTIVELY EXPLOITED VULNERABILITY</b><br><br><b>CVE:</b> ${kev.cve_id}<br><b>Name:</b> ${kev.vulnerability_name}<br><b>Added to KEV:</b> ${kev.date_added}<br><b>Required Action:</b> ${kev.required_action}<br><br><i>This vulnerability is being actively exploited in the wild!<br>Click to view CISA KEV catalog</i>`,
      group: 'kev',
      size: 22,
      level: 3,
      color: {
        border: '#880E4F',
        background: '#C2185B',
        highlight: { border: '#560027', background: '#E91E63' }
      },
      font: { size: 12, color: '#fff', bold: true },
      mass: 2,
      borderWidth: 4
    });

    edges.push({
      from: productId,
      to: kevId,
      label: 'EXPLOITED',
      width: 5,
      color: { color: '#C2185B' },
      dashes: [8, 8]
    });
  });

  // 5. ALTERNATIVES
  alternatives.forEach((alt, index) => {
    const altId = `alt_${index}`;
    const altName = alt.name || alt.product_name || 'Alternative';
    const altScore = alt.trust_score || 'N/A';

    nodes.push({
      id: altId,
      label: altName,
      title: `<b>ALTERNATIVE PRODUCT</b><br><br><b>Name:</b> ${altName}<br><b>Trust Score:</b> ${altScore}<br><br><b>Why Consider This?</b><br>${alt.rationale || 'Safer alternative with better security posture'}<br><br><i>Click to compare with current product</i>`,
      group: 'alternative',
      size: 28,
      level: 4,
      color: {
        border: '#6A1B9A',
        background: '#8E24AA',
        highlight: { border: '#4A148C', background: '#AB47BC' }
      },
      font: { size: 15, color: '#fff', bold: true },
      mass: 2
    });

    edges.push({
      from: productId,
      to: altId,
      label: 'ALTERNATIVE TO',
      width: 3,
      color: { color: '#8E24AA' },
      dashes: [10, 5],
      arrows: { to: { scaleFactor: 0.7 } }
    });
  });

  // 6. DATA SOURCES
  sources.forEach((source, index) => {
    const sourceId = `source_${index}`;
    const sourceName = source.name || 'Data Source';

    nodes.push({
      id: sourceId,
      label: sourceName,
      title: `<b>DATA SOURCE</b><br><br><b>Source:</b> ${sourceName}<br><b>Type:</b> ${source.type || 'N/A'}<br><b>Records Found:</b> ${source.count || 'N/A'}<br><br><i>This source provided data used in the security assessment</i>`,
      group: 'source',
      size: 18,
      level: 1,
      y: 150 * (index + 1),
      color: {
        border: '#00695C',
        background: '#00897B',
        highlight: { border: '#004D40', background: '#26A69A' }
      },
      font: { size: 12, color: '#fff', bold: true },
      mass: 1,
      shape: 'square'
    });

    edges.push({
      from: sourceId,
      to: productId,
      label: 'INFORMS',
      width: 2,
      color: { color: '#00897B' },
      dashes: [5, 10],
      arrows: { to: { scaleFactor: 0.6 } }
    });
  });

  return { nodes, edges };
}

// Setup graph interactions
function setupInteractions(network, tooltip, assessment) {
  // Click handler
  network.on('click', (params) => {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];

      // Open CVE in NVD
      if (nodeId.startsWith('CVE-')) {
        window.open(`https://nvd.nist.gov/vuln/detail/${nodeId}`, '_blank');
      }

      // Open KEV in CISA
      if (nodeId.startsWith('kev_CVE-')) {
        const cveId = nodeId.replace('kev_', '');
        window.open(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`, '_blank');
      }
    }
  });

  // Hover handler with custom tooltip
  network.on('hoverNode', (params) => {
    const nodeId = params.node;
    const node = network.body.data.nodes.get(nodeId);
    const connectedNodes = network.getConnectedNodes(nodeId);

    // Show custom HTML tooltip
    if (tooltip && node.title) {
      tooltip.innerHTML = node.title;
      tooltip.style.display = 'block';

      const canvasPos = network.getPositions([nodeId])[nodeId];
      const DOMPos = network.canvasToDOM(canvasPos);
      
      // Get container position
      const container = network.canvas.frame;
      const containerRect = container.getBoundingClientRect();
      
      // Calculate tooltip position (above the node)
      const tooltipHeight = tooltip.offsetHeight || 100;
      const tooltipWidth = tooltip.offsetWidth || 200;
      
      // Position tooltip above and centered on the node
      const left = DOMPos.x - tooltipWidth / 2;
      const top = DOMPos.y - tooltipHeight - 20; // 20px above the node
      
      tooltip.style.left = Math.max(0, left) + 'px';
      tooltip.style.top = Math.max(0, top) + 'px';
    }

    // Highlight connected nodes
    const allNodes = network.body.data.nodes.get();
    allNodes.forEach(n => {
      network.body.data.nodes.update({
        id: n.id,
        opacity: (n.id === nodeId || connectedNodes.includes(n.id)) ? 1.0 : 0.3
      });
    });
  });

  // Blur handler
  network.on('blurNode', () => {
    if (tooltip) {
      tooltip.style.display = 'none';
    }

    const allNodes = network.body.data.nodes.get();
    allNodes.forEach(n => {
      network.body.data.nodes.update({ id: n.id, opacity: 1.0 });
    });
  });

  // Hide tooltip on drag/zoom
  network.on('dragStart', () => {
    if (tooltip) tooltip.style.display = 'none';
  });

  network.on('zoom', () => {
    if (tooltip) tooltip.style.display = 'none';
  });
}

export default SecurityGraph;

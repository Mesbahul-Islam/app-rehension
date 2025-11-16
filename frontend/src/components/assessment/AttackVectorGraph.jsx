import { useEffect, useRef, useState } from 'react';
import { Network } from 'vis-network';
import { DataSet } from 'vis-data';
import { Target, Maximize2, Minimize2, Download, Info } from 'lucide-react';

/**
 * Interactive Attack Vector Graph
 * Shows directed graph of CVE → Technique → Tactic attack paths
 */
export default function AttackVectorGraph({ mitreData }) {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [stats, setStats] = useState({
    totalNodes: 0,
    totalEdges: 0,
    attackPaths: 0
  });

  useEffect(() => {
    if (!containerRef.current || !mitreData?.techniques) return;

    // Prepare graph data
    const graphData = buildGraphData(mitreData);
    setStats({
      totalNodes: graphData.nodes.length,
      totalEdges: graphData.edges.length,
      attackPaths: mitreData.attack_chains?.length || 0
    });

    // Create vis-network datasets
    const nodes = new DataSet(graphData.nodes);
    const edges = new DataSet(graphData.edges);

    // Network options
    const options = {
      nodes: {
        shape: 'box',
        margin: 10,
        font: {
          size: 12,
          face: 'monospace',
          color: '#1f2937'
        },
        borderWidth: 2,
        shadow: {
          enabled: true,
          color: 'rgba(0,0,0,0.1)',
          size: 5,
          x: 2,
          y: 2
        }
      },
      edges: {
        arrows: {
          to: {
            enabled: true,
            scaleFactor: 0.5
          }
        },
        smooth: {
          type: 'cubicBezier',
          forceDirection: 'horizontal',
          roundness: 0.4
        },
        color: {
          color: '#9ca3af',
          highlight: '#ef4444',
          hover: '#f59e0b'
        },
        width: 2,
        font: {
          size: 10,
          align: 'top',
          color: '#6b7280'
        }
      },
      layout: {
        hierarchical: {
          enabled: true,
          direction: 'LR', // Left to right
          sortMethod: 'directed',
          levelSeparation: 250,
          nodeSpacing: 150,
          treeSpacing: 200,
          blockShifting: true,
          edgeMinimization: true,
          parentCentralization: true
        }
      },
      physics: {
        enabled: false // Disable physics for hierarchical layout
      },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
        dragView: true,
        navigationButtons: true,
        keyboard: {
          enabled: true,
          bindToWindow: false
        }
      }
    };

    // Initialize network
    const network = new Network(
      containerRef.current,
      { nodes, edges },
      options
    );

    networkRef.current = network;

    // Event handlers
    network.on('click', (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = nodes.get(nodeId);
        setSelectedNode(node);
      } else {
        setSelectedNode(null);
      }
    });

    network.on('hoverNode', () => {
      containerRef.current.style.cursor = 'pointer';
    });

    network.on('blurNode', () => {
      containerRef.current.style.cursor = 'default';
    });

    // Initial zoom and position - focus on left side (CVE nodes)
    setTimeout(() => {
      // First fit to get initial layout
      network.fit({
        animation: false
      });
      
      // Then zoom in to 1.5x and position to show left region (CVEs and techniques)
      setTimeout(() => {
        const scale = 0.8;
        network.moveTo({
          scale: scale,
          offset: { x: 200, y: 0 }, // Shift view slightly to the right to center CVE region
          animation: {
            duration: 1000,
            easingFunction: 'easeInOutQuad'
          }
        });
      }, 100);
    }, 100);

    // Cleanup
    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
  }, [mitreData]);

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
    setTimeout(() => {
      if (networkRef.current) {
        networkRef.current.fit();
      }
    }, 100);
  };

  const exportGraph = () => {
    if (!networkRef.current) return;
    
    const canvas = containerRef.current.querySelector('canvas');
    if (canvas) {
      const link = document.createElement('a');
      link.download = 'attack-vector-graph.png';
      link.href = canvas.toDataURL();
      link.click();
    }
  };

  const resetView = () => {
    if (networkRef.current) {
      networkRef.current.fit({
        animation: {
          duration: 500,
          easingFunction: 'easeInOutQuad'
        }
      });
    }
  };

  return (
    <div className={`${isFullscreen ? 'fixed inset-0 z-50 bg-white' : 'relative'}`}>
      <div className="bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
        {/* Header */}
        <div className="bg-linear-to-r from-blue-600 to-purple-600 p-4 text-white">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Target className="w-6 h-6" />
              <div>
                <h3 className="text-xl font-bold">Attack Vector Graph</h3>
                <p className="text-sm text-blue-100">
                  Interactive visualization of CVE-based attack paths
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={resetView}
                className="p-2 hover:bg-white/20 rounded transition-colors"
                title="Reset view"
              >
                <Maximize2 className="w-5 h-5" />
              </button>
              <button
                onClick={exportGraph}
                className="p-2 hover:bg-white/20 rounded transition-colors"
                title="Export as image"
              >
                <Download className="w-5 h-5" />
              </button>
              <button
                onClick={toggleFullscreen}
                className="p-2 hover:bg-white/20 rounded transition-colors"
                title="Toggle fullscreen"
              >
                {isFullscreen ? (
                  <Minimize2 className="w-5 h-5" />
                ) : (
                  <Maximize2 className="w-5 h-5" />
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Stats Bar */}
        <div className="bg-gray-50 border-b border-gray-200 px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-red-500 rounded-full"></div>
              <span className="text-sm text-gray-700">
                <span className="font-semibold">{stats.totalNodes}</span> Nodes
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
              <span className="text-sm text-gray-700">
                <span className="font-semibold">{stats.totalEdges}</span> Attack Paths
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
              <span className="text-sm text-gray-700">
                <span className="font-semibold">{stats.attackPaths}</span> Complete Chains
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <Info className="w-4 h-4" />
            <span>Click nodes for details • Drag to pan • Scroll to zoom</span>
          </div>
        </div>

        {/* Graph Container */}
        <div className="relative">
          <div
            ref={containerRef}
            className={`bg-gray-50 ${
              isFullscreen ? 'h-[calc(100vh-180px)]' : 'h-[600px]'
            }`}
          />

          {/* Node Details Panel */}
          {selectedNode && (
            <div className="absolute top-4 right-4 bg-white rounded-lg shadow-lg border border-gray-200 p-4 max-w-sm">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <span
                    className="inline-block px-2 py-1 text-xs font-semibold rounded mb-2"
                    style={{ backgroundColor: selectedNode.color.background }}
                  >
                    {selectedNode.group}
                  </span>
                  <h4 className="font-bold text-gray-900">{selectedNode.label}</h4>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ✕
                </button>
              </div>
              
              {selectedNode.title && (
                <p className="text-sm text-gray-600 mb-2">{selectedNode.title}</p>
              )}

              {selectedNode.metadata && (
                <div className="space-y-1 text-sm">
                  {selectedNode.metadata.related_cves && (
                    <div>
                      <span className="font-semibold">Related CVEs:</span>{' '}
                      {selectedNode.metadata.related_cves.length}
                    </div>
                  )}
                  {selectedNode.metadata.tactics && (
                    <div>
                      <span className="font-semibold">Tactics:</span>{' '}
                      {selectedNode.metadata.tactics.join(', ')}
                    </div>
                  )}
                  {selectedNode.metadata.cvss && (
                    <div>
                      <span className="font-semibold">CVSS:</span>{' '}
                      {selectedNode.metadata.cvss}
                    </div>
                  )}
                </div>
              )}

              {selectedNode.url && (
                <a
                  href={selectedNode.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-3 inline-flex items-center text-sm text-blue-600 hover:text-blue-800"
                >
                  View Details →
                </a>
              )}
            </div>
          )}
        </div>

        {/* Legend */}
        <div className="bg-gray-50 border-t border-gray-200 px-4 py-3">
          <div className="flex items-center gap-6 text-sm">
            <span className="font-semibold text-gray-700">Legend:</span>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-red-100 border-2 border-red-500 rounded"></div>
              <span className="text-gray-600">CVE</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-orange-100 border-2 border-orange-500 rounded"></div>
              <span className="text-gray-600">MITRE Technique</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-purple-100 border-2 border-purple-500 rounded"></div>
              <span className="text-gray-600">Tactic</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 bg-blue-100 border-2 border-blue-500 rounded"></div>
              <span className="text-gray-600">Impact</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Build graph data from MITRE ATT&CK data
 * Creates nodes for CVEs, Techniques, Tactics, and final Impact
 */
function buildGraphData(mitreData) {
  const nodes = [];
  const edges = [];
  const nodeIds = new Set();

  // Track which tactics have been added
  const tacticNodes = new Set();
  const impactAdded = new Set();

  // Add technique nodes and their tactics
  mitreData.techniques?.forEach((tech) => {
    const techId = `tech_${tech.id}`;
    
    if (!nodeIds.has(techId)) {
      nodes.push({
        id: techId,
        label: tech.id,
        title: tech.name,
        group: 'Technique',
        level: 2, // Middle level
        color: {
          background: '#fed7aa',
          border: '#f97316',
          highlight: {
            background: '#fdba74',
            border: '#ea580c'
          }
        },
        metadata: {
          tactics: tech.tactics,
          related_cves: tech.related_cves
        },
        url: tech.url
      });
      nodeIds.add(techId);
    }

    // Add CVE nodes and connect to technique
    tech.related_cves?.slice(0, 5).forEach((cveId) => { // Limit to 5 CVEs per technique
      const cveNodeId = `cve_${cveId}`;
      
      if (!nodeIds.has(cveNodeId)) {
        nodes.push({
          id: cveNodeId,
          label: cveId,
          title: `Vulnerability: ${cveId}`,
          group: 'CVE',
          level: 1, // Leftmost level
          color: {
            background: '#fecaca',
            border: '#dc2626',
            highlight: {
              background: '#fca5a5',
              border: '#b91c1c'
            }
          },
          metadata: {
            cve_id: cveId
          }
        });
        nodeIds.add(cveNodeId);
      }

      // Edge: CVE → Technique
      edges.push({
        from: cveNodeId,
        to: techId,
        label: 'enables',
        arrows: 'to'
      });
    });

    // Add tactic nodes and connect technique to tactics
    tech.tactics?.forEach((tactic) => {
      const tacticId = `tactic_${tactic.replace(/\s+/g, '_')}`;
      
      if (!tacticNodes.has(tacticId)) {
        nodes.push({
          id: tacticId,
          label: tactic,
          title: `Tactic: ${tactic}`,
          group: 'Tactic',
          level: 3, // Right of techniques
          color: {
            background: '#e9d5ff',
            border: '#9333ea',
            highlight: {
              background: '#d8b4fe',
              border: '#7e22ce'
            }
          },
          metadata: {
            tactic: tactic
          }
        });
        tacticNodes.add(tacticId);
        nodeIds.add(tacticId);
      }

      // Edge: Technique → Tactic
      edges.push({
        from: techId,
        to: tacticId,
        label: 'executes',
        arrows: 'to'
      });

      // Add Impact node for final tactics
      const finalTactics = ['Exfiltration', 'Impact', 'Command And Control'];
      if (finalTactics.includes(tactic)) {
        const impactId = 'impact_final';
        
        if (!impactAdded.has(impactId)) {
          nodes.push({
            id: impactId,
            label: 'System\nCompromise',
            title: 'Final Impact: System Compromised',
            group: 'Impact',
            level: 4, // Rightmost level
            color: {
              background: '#dbeafe',
              border: '#2563eb',
              highlight: {
                background: '#bfdbfe',
                border: '#1d4ed8'
              }
            },
            font: {
              size: 16,
              bold: true
            },
            metadata: {
              type: 'final_impact'
            }
          });
          impactAdded.add(impactId);
          nodeIds.add(impactId);
        }

        // Edge: Tactic → Impact
        edges.push({
          from: tacticId,
          to: impactId,
          label: 'leads to',
          arrows: 'to',
          color: {
            color: '#dc2626',
            highlight: '#b91c1c'
          },
          width: 3
        });
      }
    });
  });

  return { nodes, edges };
}

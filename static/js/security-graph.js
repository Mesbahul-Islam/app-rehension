/**
 * Security Ecosystem Graph Module
 * Creates an interactive knowledge graph showing relationships between
 * products, vendors, CVEs, alternatives, and data sources
 * 
 * Uses Vis.js Network for force-directed graph visualization
 */

let networkInstance = null;
let currentAssessment = null;

/**
 * Initialize and render the security ecosystem graph
 * @param {Object} assessment - The full assessment data
 */
function renderSecurityEcosystemGraph(assessment) {
    currentAssessment = assessment;
    
    const container = document.getElementById('securityGraph');
    if (!container) {
        console.error('Security graph container not found');
        return;
    }
    
    // Build graph data structure
    const { nodes, edges } = buildGraphData(assessment);
    
    // Configure graph appearance and physics
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
                color: '#000',
                background: 'rgba(255, 255, 255, 0.9)',
                strokeWidth: 3,
                strokeColor: '#ffffff',
                bold: true
            }
        },
        physics: {
            enabled: false  // Disable physics for hierarchical layout
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            navigationButtons: true,
            keyboard: true,
            zoomView: true,
            dragView: true,
            tooltipStyle: 'width: 400px; max-width: 400px; font-size: 14px; line-height: 1.6; padding: 12px; background: white; border: 2px solid #333; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.2);'
        },
        nodes: {
            chosen: {
                node: function(values, id, selected, hovering) {
                    if (hovering) {
                        values.borderWidth = 4;
                    }
                }
            }
        },
        layout: {
            hierarchical: {
                enabled: true,
                direction: 'LR',  // Left to Right (linear horizontal)
                sortMethod: 'directed',  // Directed graph
                levelSeparation: 250,  // Horizontal spacing between levels
                nodeSpacing: 150,  // Vertical spacing between nodes
                treeSpacing: 200,
                blockShifting: true,
                edgeMinimization: true,
                parentCentralization: true
            }
        }
    };
    
    // Create network
    const data = { nodes: nodes, edges: edges };
    networkInstance = new vis.Network(container, data, options);
    
    // Create custom HTML tooltip element
    createCustomTooltip(container);
    
    // Add event listeners
    setupGraphInteractions(networkInstance, assessment);
    
    // Log graph statistics
    console.log(`Security graph created: ${nodes.length} nodes, ${edges.length} edges`);
}

/**
 * Create custom HTML tooltip element for rich tooltips
 * @param {HTMLElement} container - Graph container element
 */
function createCustomTooltip(container) {
    // Remove existing tooltip if any
    const existingTooltip = document.getElementById('graph-custom-tooltip');
    if (existingTooltip) {
        existingTooltip.remove();
    }
    
    // Create tooltip element
    const tooltip = document.createElement('div');
    tooltip.id = 'graph-custom-tooltip';
    tooltip.style.cssText = `
        position: absolute;
        display: none;
        max-width: 400px;
        padding: 12px 16px;
        background: white;
        border: 2px solid #333;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        font-size: 14px;
        line-height: 1.6;
        z-index: 1000;
        pointer-events: none;
    `;
    document.body.appendChild(tooltip);
}

/**
 * Build nodes and edges from assessment data
 * @param {Object} assessment - Assessment data
 * @returns {Object} Object containing nodes and edges arrays
 */
function buildGraphData(assessment) {
    const nodes = [];
    const edges = [];
    
    const entity = assessment.entity;
    const security = assessment.security_posture;
    const alternatives = assessment.alternatives || [];
    const sources = assessment.sources || [];
    
    // 1. PRODUCT NODE (center, large)
    const productId = 'product';
    const productName = entity.product_name || entity.vendor || 'Unknown Product';
    nodes.push({
        id: productId,
        label: productName,
        title: `<b>🎯 PRIMARY PRODUCT</b><br><br><b>Name:</b> ${productName}<br><b>Trust Score:</b> ${assessment.trust_score.total_score}/100<br><b>Category:</b> ${assessment.classification.category}<br><b>Risk Level:</b> ${assessment.classification.risk_level}<br><br><i>Click to see full details</i>`,
        group: 'product',
        size: 45,
        level: 2,  // Center level
        color: {
            border: '#1565C0',
            background: '#1E88E5',
            highlight: {
                border: '#0D47A1',
                background: '#42A5F5'
            }
        },
        font: { size: 20, color: '#fff', bold: true },
        mass: 5  // Heavy node to stay central
    });
    
    // 2. VENDOR NODE
    if (entity.vendor) {
        const vendorId = 'vendor';
        nodes.push({
            id: vendorId,
            label: entity.vendor,
            title: `<b>🏢 VENDOR / MANUFACTURER</b><br><br><b>Company:</b> ${entity.vendor}<br><br><i>The organization that develops and maintains this product</i>`,
            group: 'vendor',
            size: 32,
            level: 0,  // Leftmost - source
            color: {
                border: '#2E7D32',
                background: '#43A047',
                highlight: {
                    border: '#1B5E20',
                    background: '#66BB6A'
                }
            },
            font: { size: 17, color: '#fff', bold: true },
            mass: 3
        });
        
        // Edge: Vendor → Product (owns)
        edges.push({
            from: vendorId,
            to: productId,
            label: 'DEVELOPS',
            width: 5,
            color: { color: '#43A047' },
            arrows: { to: { scaleFactor: 1.0 } }
        });
    }
    
    // 3. CVE NODES (recent/critical vulnerabilities)
    const recentCVEs = security.recent_cves || [];
    const maxCVEs = 15; // Limit to prevent clutter
    
    recentCVEs.slice(0, maxCVEs).forEach((cve, index) => {
        const cveId = cve.cve_id;
        const severity = cve.severity || 'UNKNOWN';
        const cvssScore = cve.cvss_v3 || 'N/A';
        
        // Color based on severity - more distinct and vibrant colors
        const severityColors = {
            'CRITICAL': { border: '#B71C1C', background: '#D32F2F', icon: '🔴' },
            'HIGH': { border: '#E65100', background: '#FF6F00', icon: '🟠' },
            'MEDIUM': { border: '#F57F17', background: '#FBC02D', icon: '🟡' },
            'LOW': { border: '#455A64', background: '#607D8B', icon: '🔵' },
            'UNKNOWN': { border: '#424242', background: '#616161', icon: '⚪' }
        };
        
        const colors = severityColors[severity] || severityColors['UNKNOWN'];
        const icon = colors.icon;
        
        nodes.push({
            id: cveId,
            label: `${icon} ${cveId}`,
            title: `<b>🐛 VULNERABILITY</b><br><br><b>CVE ID:</b> ${cveId}<br><b>Severity:</b> ${severity}<br><b>CVSS Score:</b> ${cvssScore}<br><br>${cve.summary ? '<b>Description:</b><br>' + cve.summary.substring(0, 200) + '...' : ''}<br><br><i>Click to view on NVD database</i>`,
            group: 'cve',
            size: 14 + (severity === 'CRITICAL' ? 8 : severity === 'HIGH' ? 5 : 2),
            level: 3,  // Right of product - affected by
            color: {
                border: colors.border,
                background: colors.background,
                highlight: {
                    border: colors.border,
                    background: colors.background
                }
            },
            font: { size: 11, color: '#fff', bold: true },
            mass: 1
        });
        
        // Edge: CVE → Product (affects)
        edges.push({
            from: productId,
            to: cveId,
            label: severity === 'CRITICAL' ? 'CRITICAL VULN' : severity === 'HIGH' ? 'HIGH VULN' : 'HAS VULN',
            width: severity === 'CRITICAL' ? 4 : severity === 'HIGH' ? 3 : 2,
            color: { color: colors.background },
            dashes: false
        });
    });
    
    // 4. KEV NODES (Known Exploited Vulnerabilities)
    const kevList = security.kev_list || [];
    
    kevList.forEach((kev, index) => {
        const kevId = `kev_${kev.cve_id}`;
        
        nodes.push({
            id: kevId,
            label: `⚠️ ${kev.cve_id}`,
            title: `<b>⚠️ ACTIVELY EXPLOITED VULNERABILITY</b><br><br><b>CVE:</b> ${kev.cve_id}<br><b>Name:</b> ${kev.vulnerability_name}<br><b>Added to KEV:</b> ${kev.date_added}<br><b>Required Action:</b> ${kev.required_action}<br><br><i>This vulnerability is being actively exploited in the wild!<br>Click to view CISA KEV catalog</i>`,
            group: 'kev',
            size: 22,
            level: 3,  // Same level as CVEs
            color: {
                border: '#880E4F',
                background: '#C2185B',
                highlight: {
                    border: '#560027',
                    background: '#E91E63'
                }
            },
            font: { size: 12, color: '#fff', bold: true },
            mass: 2,
            borderWidth: 4
        });
        
        // Edge: KEV → Product (actively exploited)
        edges.push({
            from: productId,
            to: kevId,
            label: '⚠️ EXPLOITED',
            width: 5,
            color: { color: '#C2185B' },
            dashes: [8, 8]  // Dashed line for urgency
        });
    });
    
    // 5. ALTERNATIVE PRODUCTS
    alternatives.forEach((alt, index) => {
        const altId = `alt_${index}`;
        const altName = alt.name || alt.product_name || 'Alternative';
        const altScore = alt.trust_score || 'N/A';
        
        nodes.push({
            id: altId,
            label: `🔄 ${altName}`,
            title: `<b>💡 ALTERNATIVE PRODUCT</b><br><br><b>Name:</b> ${altName}<br><b>Trust Score:</b> ${altScore}<br><br><b>Why Consider This?</b><br>${alt.rationale || 'Safer alternative with better security posture'}<br><br><i>Click to compare with current product</i>`,
            group: 'alternative',
            size: 28,
            level: 4,  // Rightmost - alternatives
            color: {
                border: '#6A1B9A',
                background: '#8E24AA',
                highlight: {
                    border: '#4A148C',
                    background: '#AB47BC'
                }
            },
            font: { size: 15, color: '#fff', bold: true },
            mass: 2
        });
        
        // Edge: Product → Alternative (similar to)
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
    
    // 6. DATA SOURCE NODES
    sources.forEach((source, index) => {
        const sourceId = `source_${index}`;
        const sourceName = source.name || 'Data Source';
        
        nodes.push({
            id: sourceId,
            label: `📊 ${sourceName}`,
            title: `<b>📊 DATA SOURCE</b><br><br><b>Source:</b> ${sourceName}<br><b>Type:</b> ${source.type || 'N/A'}<br><b>Records Found:</b> ${source.count || 'N/A'}<br><br><i>This source provided data used in the security assessment</i>`,
            group: 'source',
            size: 18,
            level: 1,  // Between vendor and product
            color: {
                border: '#00695C',
                background: '#00897B',
                highlight: {
                    border: '#004D40',
                    background: '#26A69A'
                }
            },
            font: { size: 12, color: '#fff', bold: true },
            mass: 1,
            shape: 'square'  // Different shape for data sources
        });
        
        // Edge: Data Source → Product (provides data)
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

/**
 * Setup interactive behaviors for the graph
 * @param {vis.Network} network - Vis.js network instance
 * @param {Object} assessment - Assessment data
 */
function setupGraphInteractions(network, assessment) {
    const tooltip = document.getElementById('graph-custom-tooltip');
    
    // Click on node
    network.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            handleNodeClick(nodeId, assessment);
        }
    });
    
    // Show custom HTML tooltip on hover
    network.on('hoverNode', function(params) {
        const nodeId = params.node;
        const node = network.body.data.nodes.get(nodeId);
        const connectedNodes = network.getConnectedNodes(nodeId);
        
        // Show custom tooltip with HTML content
        if (tooltip && node.title) {
            tooltip.innerHTML = node.title;
            tooltip.style.display = 'block';
            
            // Position tooltip near cursor
            const canvasPos = network.getPositions([nodeId])[nodeId];
            const DOMPos = network.canvasToDOM(canvasPos);
            const container = document.getElementById('securityGraph');
            const containerRect = container.getBoundingClientRect();
            
            tooltip.style.left = (containerRect.left + DOMPos.x + 20) + 'px';
            tooltip.style.top = (containerRect.top + DOMPos.y - 20) + 'px';
        }
        
        // Dim all nodes except connected ones
        const allNodes = network.body.data.nodes.get();
        allNodes.forEach(node => {
            if (node.id === nodeId || connectedNodes.includes(node.id)) {
                // Keep original opacity
                network.body.data.nodes.update({
                    id: node.id,
                    opacity: 1.0
                });
            } else {
                // Dim unrelated nodes
                network.body.data.nodes.update({
                    id: node.id,
                    opacity: 0.3
                });
            }
        });
    });
    
    // Reset on blur and hide tooltip
    network.on('blurNode', function(params) {
        // Hide tooltip
        if (tooltip) {
            tooltip.style.display = 'none';
        }
        
        const allNodes = network.body.data.nodes.get();
        allNodes.forEach(node => {
            network.body.data.nodes.update({
                id: node.id,
                opacity: 1.0
            });
        });
    });
    
    // Hide tooltip when mouse leaves the graph
    network.on('blurNode', function() {
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    });
    
    // Also hide tooltip on drag or zoom
    network.on('dragStart', function() {
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    });
    
    network.on('zoom', function() {
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    });
}

/**
 * Handle click on a graph node
 * @param {string} nodeId - ID of clicked node
 * @param {Object} assessment - Assessment data
 */
function handleNodeClick(nodeId, assessment) {
    console.log('Clicked node:', nodeId);
    
    // Handle CVE node clicks - open NVD link
    if (nodeId.startsWith('CVE-')) {
        const nvdUrl = `https://nvd.nist.gov/vuln/detail/${nodeId}`;
        window.open(nvdUrl, '_blank');
        return;
    }
    
    // Handle KEV node clicks - open CISA link
    if (nodeId.startsWith('kev_CVE-')) {
        const cveId = nodeId.replace('kev_', '');
        const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`;
        window.open(cisaUrl, '_blank');
        return;
    }
    
    // Handle product node - show detailed tooltip
    if (nodeId === 'product') {
        showNodeDetails('product', assessment);
    }
    
    // Handle alternative nodes - could trigger comparison
    if (nodeId.startsWith('alt_')) {
        console.log('Alternative product clicked - could trigger comparison');
    }
}

/**
 * Show detailed information about a node in a modal or expanded view
 * @param {string} nodeId - Node ID
 * @param {Object} assessment - Assessment data
 */
function showNodeDetails(nodeId, assessment) {
    // Could implement a modal popup with detailed information
    console.log('Showing details for:', nodeId);
    // For now, just log - could expand this feature
}

/**
 * Filter graph by CVE severity
 * @param {string} severity - 'all', 'critical', 'high', or 'critical_high'
 */
function filterGraphBySeverity(severity) {
    if (!networkInstance || !currentAssessment) {
        console.warn('Graph not initialized');
        return;
    }
    
    // Rebuild graph with filtered data
    const { nodes, edges } = buildGraphData(currentAssessment);
    
    if (severity !== 'all') {
        // Filter CVE nodes
        const filteredNodes = nodes.filter(node => {
            if (node.group !== 'cve') return true; // Keep non-CVE nodes
            
            const cve = currentAssessment.security_posture.recent_cves.find(c => c.cve_id === node.id);
            if (!cve) return false;
            
            if (severity === 'critical') {
                return cve.severity === 'CRITICAL';
            } else if (severity === 'high') {
                return cve.severity === 'HIGH';
            } else if (severity === 'critical_high') {
                return cve.severity === 'CRITICAL' || cve.severity === 'HIGH';
            }
            
            return true;
        });
        
        // Filter edges connected to removed CVE nodes
        const nodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredEdges = edges.filter(edge => 
            nodeIds.has(edge.from) && nodeIds.has(edge.to)
        );
        
        networkInstance.setData({ nodes: filteredNodes, edges: filteredEdges });
    } else {
        // Show all
        networkInstance.setData({ nodes, edges });
    }
    
    console.log(`Graph filtered by severity: ${severity}`);
}

/**
 * Re-center the graph view on the product node
 */
function centerGraphOnProduct() {
    if (!networkInstance) {
        console.warn('Graph not initialized');
        return;
    }
    
    networkInstance.focus('product', {
        scale: 1.0,
        animation: {
            duration: 1000,
            easingFunction: 'easeInOutQuad'
        }
    });
}

/**
 * Export graph as PNG image
 */
function exportGraphAsPNG() {
    if (!networkInstance) {
        console.warn('Graph not initialized');
        return;
    }
    
    const canvas = document.querySelector('#securityGraph canvas');
    if (canvas) {
        const link = document.createElement('a');
        link.download = 'security-ecosystem-graph.png';
        link.href = canvas.toDataURL('image/png');
        link.click();
        console.log('Graph exported as PNG');
    } else {
        console.error('Canvas not found');
    }
}

/**
 * Toggle graph physics simulation
 */
function toggleGraphPhysics() {
    if (!networkInstance) return;
    
    const currentPhysics = networkInstance.physics.options.enabled;
    networkInstance.setOptions({ physics: { enabled: !currentPhysics } });
    console.log(`Graph physics ${!currentPhysics ? 'enabled' : 'disabled'}`);
}

/**
 * Get graph statistics
 * @returns {Object} Statistics about the graph
 */
function getGraphStats() {
    if (!networkInstance || !currentAssessment) return null;
    
    const nodes = networkInstance.body.data.nodes.get();
    const edges = networkInstance.body.data.edges.get();
    
    const nodesByType = nodes.reduce((acc, node) => {
        acc[node.group] = (acc[node.group] || 0) + 1;
        return acc;
    }, {});
    
    return {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        nodesByType: nodesByType,
        cveCount: nodesByType.cve || 0,
        kevCount: nodesByType.kev || 0,
        alternativeCount: nodesByType.alternative || 0,
        sourceCount: nodesByType.source || 0
    };
}

// Export functions for global access
window.renderSecurityEcosystemGraph = renderSecurityEcosystemGraph;
window.filterGraphBySeverity = filterGraphBySeverity;
window.centerGraphOnProduct = centerGraphOnProduct;
window.exportGraphAsPNG = exportGraphAsPNG;
window.toggleGraphPhysics = toggleGraphPhysics;
window.getGraphStats = getGraphStats;

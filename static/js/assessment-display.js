/**
 * Assessment Display Module
 * Handles rendering of security assessment results
 */

/**
 * Display the complete assessment results
 * @param {Object} assessment - The assessment data object
 */
function displayAssessment(assessment) {
    const content = document.getElementById('resultsContent');
    
    console.log('Full assessment object:', assessment);
    
    // Determine if this is a VirusTotal analysis
    const isVirusTotalAnalysis = assessment.metadata?.virustotal_analysis === true;
    const virustotal = assessment.virustotal;
    
    const entity = assessment.entity;
    const classification = assessment.classification;
    const security = assessment.security_posture;
    const trustScore = assessment.trust_score;
    const securityPractices = assessment.security_practices;
    const incidents = assessment.incidents;
    const dataCompliance = assessment.data_compliance;
    const deploymentControls = assessment.deployment_controls;
    const alternatives = assessment.alternatives;
    
    console.log('Assessment type:', isVirusTotalAnalysis ? 'VirusTotal File Analysis' : 'Product/Vendor Analysis');
    console.log('Extracted dataCompliance:', dataCompliance);
    console.log('Extracted deploymentControls:', deploymentControls);
    console.log('Trust score object:', trustScore);
    
    // Build trust score color
    const score = trustScore.score || trustScore.total_score || 0;
    let scoreColor = '#27ae60';
    if (score < 40) scoreColor = '#c33';
    else if (score < 60) scoreColor = '#e67e22';
    else if (score < 75) scoreColor = '#f39c12';
    
    let html = `
        ${renderInputMetadata(assessment)}
        ${renderEntityInfo(entity, classification, isVirusTotalAnalysis)}
        ${renderTrustScore(trustScore, scoreColor, isVirusTotalAnalysis)}
        ${renderSecurityEcosystemGraphCard()}
    `;
    
    // Conditional sections based on analysis type
    if (isVirusTotalAnalysis) {
        // VirusTotal-specific sections
        html += `
            ${renderVirusTotalDetectionDetails(virustotal)}
            ${renderVirusTotalThreatAnalysis(virustotal)}
            ${renderSecurityPosture(security)}
        `;
    } else {
        // Standard product/vendor sections
        html += `
            ${renderSecurityPractices(securityPractices)}
            ${renderIncidents(incidents)}
            ${renderDataCompliance(dataCompliance)}
            ${renderDeploymentControls(deploymentControls)}
            ${renderSecurityPosture(security)}
        `;
    }
    
    // Alternatives - show for all analysis types
    html += renderAlternatives(alternatives);
    
    // Common sections
    html += renderMetadata(assessment);
    
    content.innerHTML = html;
    
    // Initialize Security Ecosystem Graph
    setTimeout(() => {
        if (typeof renderSecurityEcosystemGraph === 'function') {
            renderSecurityEcosystemGraph(assessment);
        } else {
            console.error('Security graph function not loaded');
        }
    }, 100);
    
    // Initialize CVE timeline chart after DOM is updated
    const cveTimeline = security?.vulnerability_summary?.cve_timeline;
    if (cveTimeline && Object.keys(cveTimeline).length > 0) {
        console.log('Initializing CVE timeline chart with data:', cveTimeline);
        
        // Add event listener to details element to render chart when opened
        const detailsElement = document.getElementById('cveTimelineDetails');
        if (detailsElement) {
            detailsElement.addEventListener('toggle', function() {
                if (this.open) {
                    console.log('Details opened, creating chart...');
                    // Use setTimeout to ensure the canvas is visible and has dimensions
                    setTimeout(() => {
                        createCVETimelineChart(cveTimeline);
                    }, 50);
                }
            });
            
            // If details is open by default, create chart immediately
            if (detailsElement.open) {
                setTimeout(() => {
                    createCVETimelineChart(cveTimeline);
                }, 100);
            }
        }
    }
}

function renderInputMetadata(assessment) {
    const inputMetadata = assessment._input_metadata;
    if (!inputMetadata) return '';
    
    // Check if this assessment came from a SHA1 hash lookup
    if (inputMetadata.parsed_type === 'sha1' && inputMetadata.virustotal_data) {
        const vt = inputMetadata.virustotal_data;
        const detectionStats = vt.detection_stats || {};
        const totalScans = Object.values(detectionStats).reduce((a, b) => a + b, 0);
        const malicious = detectionStats.malicious || 0;
        const suspicious = detectionStats.suspicious || 0;
        const detectionCount = malicious + suspicious;
        
        // Determine alert level based on detections
        let alertColor = '#27ae60'; // Green - clean
        let alertIcon = '✅';
        let alertText = 'Clean';
        
        if (malicious > 0) {
            alertColor = '#c33'; // Red - malicious
            alertIcon = '🚨';
            alertText = 'Malicious Detections Found';
        } else if (suspicious > 0) {
            alertColor = '#f39c12'; // Orange - suspicious
            alertIcon = '⚠️';
            alertText = 'Suspicious Activity Detected';
        }
        
        return `
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
                <h3 style="color: white; margin-top: 0;">🔍 VirusTotal Analysis</h3>
                <p style="margin-bottom: 1rem;">
                    This assessment was generated from a <strong>SHA1 hash lookup</strong> using VirusTotal.
                </p>
                
                <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                    <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 0.5rem; font-size: 0.9rem;">
                        <strong>SHA1 Hash:</strong>
                        <code style="background: rgba(0,0,0,0.2); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; word-break: break-all;">${inputMetadata.sha1}</code>
                        
                        <strong>File Name:</strong>
                        <span>${vt.primary_name || 'Unknown'}</span>
                        
                        <strong>File Type:</strong>
                        <span>${vt.type || vt.file_type || 'Unknown'}</span>
                        
                        <strong>File Size:</strong>
                        <span>${vt.size ? formatBytes(vt.size) : 'Unknown'}</span>
                        
                        ${vt.last_analysis_date ? `
                            <strong>Last Scanned:</strong>
                            <span>${new Date(vt.last_analysis_date).toLocaleDateString()}</span>
                        ` : ''}
                    </div>
                </div>
                
                <div style="background: ${alertColor}; color: white; padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                    <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem;">
                        <span style="font-size: 2rem;">${alertIcon}</span>
                        <div>
                            <strong style="font-size: 1.2rem; display: block;">${alertText}</strong>
                            <span style="font-size: 1.5rem; font-weight: bold;">${vt.detection_ratio} detections</span>
                        </div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.5rem; margin-top: 1rem; font-size: 0.9rem;">
                        <div>
                            <strong>Malicious:</strong> ${malicious}
                        </div>
                        <div>
                            <strong>Suspicious:</strong> ${suspicious}
                        </div>
                        <div>
                            <strong>Undetected:</strong> ${detectionStats.undetected || 0}
                        </div>
                        <div>
                            <strong>Harmless:</strong> ${detectionStats.harmless || 0}
                        </div>
                    </div>
                </div>
                
                ${vt.signature ? `
                    <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                        <strong style="display: block; margin-bottom: 0.5rem;">📝 Digital Signature:</strong>
                        <div style="font-size: 0.9rem; line-height: 1.6;">
                            ${vt.signature.verified ? `<div>✅ <strong>Verified:</strong> ${vt.signature.verified}</div>` : ''}
                            ${vt.signature.product ? `<div><strong>Product:</strong> ${vt.signature.product}</div>` : ''}
                            ${vt.signature.signers ? `<div><strong>Signers:</strong> ${vt.signature.signers}</div>` : ''}
                            ${vt.signature.copyright ? `<div><strong>Copyright:</strong> ${vt.signature.copyright}</div>` : ''}
                        </div>
                    </div>
                ` : ''}
                
                ${vt.threat_classification ? `
                    <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                        <strong style="display: block; margin-bottom: 0.5rem;">🎯 Threat Classification:</strong>
                        <div style="font-size: 0.9rem;">
                            ${vt.threat_classification.suggested_threat_label || 'N/A'}
                        </div>
                    </div>
                ` : ''}
                
                <div style="margin-top: 1rem;">
                    <a href="${vt.source_url}" target="_blank" style="color: white; text-decoration: underline;">
                        🔗 View full report on VirusTotal
                    </a>
                </div>
            </div>
        `;
    }
    
    // Show other input metadata if available
    if (inputMetadata.parsed_type === 'vendor_product') {
        return `
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; border-left: 4px solid #3498db;">
                <strong>ℹ️ Input Format Detected:</strong> Vendor + Product
                <br>
                <span style="font-size: 0.9rem; color: #666;">
                    Vendor: <strong>${inputMetadata.detected_vendor}</strong> | 
                    Product: <strong>${inputMetadata.detected_product}</strong>
                </span>
            </div>
        `;
    }
    
    return '';
}

// Helper function to format bytes
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function renderEntityInfo(entity, classification, isVirusTotalAnalysis) {
    // Determine if this is a product or vendor-only assessment
    const isVendorOnly = !entity.product_name;
    const title = isVendorOnly ? entity.vendor : entity.product_name;
    
    // Different display for VirusTotal analysis
    if (isVirusTotalAnalysis) {
        return `
            <div style="margin-bottom: 2rem;">
                <h3>📦 File Analysis: ${title}</h3>
                ${entity.vendor ? `<p><strong>Publisher/Vendor:</strong> ${entity.vendor}</p>` : ''}
                ${entity.url ? `<p><strong>Source:</strong> <a href="${entity.url}" target="_blank">View on VirusTotal</a></p>` : ''}
                <p><strong>Analysis Type:</strong> File Hash Security Assessment</p>
            </div>
        `;
    }
    
    const assessmentType = isVendorOnly ? '(Vendor Assessment)' : '';
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>${title} ${assessmentType}</h3>
            ${isVendorOnly ? '' : `<p><strong>Vendor:</strong> ${entity.vendor}</p>`}
            ${entity.url ? `<p><strong>Website:</strong> <a href="${entity.url}" target="_blank">${entity.url}</a></p>` : ''}
            <p><strong>Category:</strong> ${classification.category} - ${classification.sub_category}</p>
        </div>
    `;
}

function renderTrustScore(trustScore, scoreColor, isVirusTotalAnalysis) {
    const score = trustScore.score || trustScore.total_score || 0;
    
    // Different title based on analysis type
    const titleIcon = isVirusTotalAnalysis ? '🛡️' : '🎯';
    const titleText = isVirusTotalAnalysis ? 'File Security Score' : 'Trust Score';
    const scoreType = isVirusTotalAnalysis ? '(VirusTotal Analysis)' : '(CVSS + EPSS + KEV)';
    
    // Use appropriate rendering based on analysis type
    const componentsHtml = isVirusTotalAnalysis ? renderVirusTotalComponents(trustScore) : renderNewScoringBreakdown(trustScore);
    
    // Generate formula explanation based on analysis type
    const formulaHtml = isVirusTotalAnalysis ? 
        generateVirusTotalFormulaExplanation(trustScore) : 
        generateStandardFormulaExplanation(trustScore);
    
    return `
        <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
            <h3>${titleIcon} ${titleText} ${scoreType}</h3>
            <div style="font-size: 3rem; font-weight: bold; color: ${scoreColor}; margin: 1rem 0;">
                ${score}/100
            </div>
            <p><strong>Risk Level:</strong> <span class="badge ${trustScore.risk_level}">${trustScore.risk_level.toUpperCase()}</span></p>
            <p><strong>Confidence:</strong> ${trustScore.confidence}</p>
            
            <details open style="margin-top: 1.5rem;">
                <summary style="cursor: pointer; font-weight: bold; font-size: 1.1rem; margin-bottom: 1rem;">
                    📊 Scoring Breakdown
                </summary>
                <div style="background: white; padding: 1rem; border-radius: 6px;">
                    <p style="margin-bottom: 1rem; color: #666;">
                        ${isVirusTotalAnalysis ? 
                            'This score uses <strong>transparent rule-based calculations</strong> - not AI-generated scores. Each component has fixed weights and deterministic formulas based on VirusTotal detection data.' : 
                            'This score uses <strong>industry-standard security metrics</strong>: CVSS (vulnerability severity), EPSS (exploit probability), and KEV (known exploited vulnerabilities). No AI, no opinions - just data-driven risk assessment.'}
                    </p>
                    ${componentsHtml}
                    ${trustScore.calculation_method || trustScore.rationale ? `
                    <div style="margin-top: 1rem; padding: 1rem; background: #e8f4f8; border-radius: 6px; border-left: 4px solid #3498db;">
                        <strong>${trustScore.calculation_method ? 'Calculation Method' : 'Assessment'}:</strong> ${trustScore.calculation_method || trustScore.rationale}
                    </div>
                    ` : ''}
                </div>
            </details>
            
            <details style="margin-top: 1rem;">
                <summary style="cursor: pointer; font-weight: bold; font-size: 1rem; color: #667eea; margin-bottom: 1rem;">
                    🔬 Get to know how the score is calculated
                </summary>
                <div style="background: white; padding: 1.5rem; border-radius: 6px; border: 2px solid #667eea;">
                    ${formulaHtml}
                </div>
            </details>
        </div>
    `;
}

/**
 * Render VirusTotal component-based scoring (for file analysis only)
 */
function renderVirusTotalComponents(trustScore) {
    if (!trustScore.components) {
        return '<p style="color: #666;">Scoring details not available.</p>';
    }
    
    return Object.entries(trustScore.components).map(([key, comp]) => {
        const scorePercentage = (comp.score / comp.max_points * 100).toFixed(0);
        const barColor = scorePercentage > 70 ? '#27ae60' : scorePercentage > 50 ? '#f39c12' : '#c33';
        return `
            <div style="margin-bottom: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div>
                        <strong style="text-transform: capitalize;">${key.replace(/_/g, ' ')}</strong>
                        <span style="background: #667eea; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: 0.5rem;">
                            ${comp.weight_percentage}% weight
                        </span>
                    </div>
                    <span style="font-size: 1.2rem; font-weight: bold; color: ${barColor};">
                        ${comp.score.toFixed(1)}/${comp.max_points} pts
                    </span>
                </div>
                <div style="background: #ddd; height: 20px; border-radius: 10px; overflow: hidden; margin-bottom: 0.5rem;">
                    <div style="background: ${barColor}; height: 100%; width: ${scorePercentage}%; transition: width 0.3s;"></div>
                </div>
                <div style="font-size: 0.9rem; color: #666;">
                    ${comp.explanation}
                </div>
            </div>
        `;
    }).join('');
}

/**
 * Render the new CVSS+EPSS+KEV scoring breakdown
 */
function renderNewScoringBreakdown(trustScore) {
    const breakdown = trustScore.scoring_breakdown;
    if (!breakdown) {
        return '<p style="color: #666;">Scoring details not available.</p>';
    }
    
    const cvssRisk = breakdown.cvss_risk || 0;
    const epssRisk = breakdown.epss_risk || 0;
    const kevRisk = breakdown.kev_risk || 0;
    const totalRisk = breakdown.total_risk || 0;
    
    return `
        <div style="margin-bottom: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 6px;">
            <h4 style="margin-top: 0;">Risk Components</h4>
            
            <div style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div>
                        <strong>CVSS Risk</strong>
                        <span style="background: #667eea; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: 0.5rem;">
                            50% weight
                        </span>
                    </div>
                    <span style="font-size: 1.2rem; font-weight: bold; color: ${cvssRisk > 0.7 ? '#c33' : cvssRisk > 0.4 ? '#f39c12' : '#27ae60'};">
                        ${(cvssRisk * 10).toFixed(1)}/10 severity
                    </span>
                </div>
                <div style="background: #ddd; height: 20px; border-radius: 10px; overflow: hidden;">
                    <div style="background: ${cvssRisk > 0.7 ? '#c33' : cvssRisk > 0.4 ? '#f39c12' : '#27ae60'}; height: 100%; width: ${cvssRisk * 100}%; transition: width 0.3s;"></div>
                </div>
                <div style="font-size: 0.9rem; color: #666; margin-top: 0.5rem;">
                    Based on vulnerability severity scores from CVSS
                </div>
            </div>
            
            <div style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div>
                        <strong>EPSS Risk</strong>
                        <span style="background: #667eea; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: 0.5rem;">
                            40% weight
                        </span>
                    </div>
                    <span style="font-size: 1.2rem; font-weight: bold; color: ${epssRisk > 0.5 ? '#c33' : epssRisk > 0.2 ? '#f39c12' : '#27ae60'};">
                        ${(epssRisk * 100).toFixed(1)}% exploit probability
                    </span>
                </div>
                <div style="background: #ddd; height: 20px; border-radius: 10px; overflow: hidden;">
                    <div style="background: ${epssRisk > 0.5 ? '#c33' : epssRisk > 0.2 ? '#f39c12' : '#27ae60'}; height: 100%; width: ${epssRisk * 100}%; transition: width 0.3s;"></div>
                </div>
                <div style="font-size: 0.9rem; color: #666; margin-top: 0.5rem;">
                    Based on exploit prediction from FIRST.org EPSS
                </div>
            </div>
            
            <div style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div>
                        <strong>KEV Risk</strong>
                        <span style="background: #667eea; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: 0.5rem;">
                            10% weight
                        </span>
                    </div>
                    <span style="font-size: 1.2rem; font-weight: bold; color: ${kevRisk === 1 ? '#c33' : '#27ae60'};">
                        ${kevRisk === 1 ? '⚠️ Active exploits' : '✅ No active exploits'}
                    </span>
                </div>
                <div style="background: #ddd; height: 20px; border-radius: 10px; overflow: hidden;">
                    <div style="background: ${kevRisk === 1 ? '#c33' : '#27ae60'}; height: 100%; width: ${kevRisk * 100}%; transition: width 0.3s;"></div>
                </div>
                <div style="font-size: 0.9rem; color: #666; margin-top: 0.5rem;">
                    Based on CISA Known Exploited Vulnerabilities catalog
                </div>
            </div>
            
            <div style="margin-top: 1.5rem; padding: 1rem; background: white; border-radius: 6px; border-left: 4px solid #667eea;">
                <strong>Total Risk Score:</strong> ${(totalRisk * 100).toFixed(1)}% 
                → <strong>Trust Score:</strong> ${((1 - totalRisk) * 100).toFixed(1)}/100
            </div>
            
            ${trustScore.key_factors && trustScore.key_factors.length > 0 ? `
                <div style="margin-top: 1rem; padding: 1rem; background: #fff3cd; border-radius: 6px; border-left: 4px solid #ffc107;">
                    <strong>Key Factors:</strong>
                    <ul style="margin: 0.5rem 0 0 0; padding-left: 1.5rem;">
                        ${trustScore.key_factors.map(f => `<li>${f}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${trustScore.data_limitations && trustScore.data_limitations.length > 0 ? `
                <div style="margin-top: 1rem; padding: 0.75rem; background: #e8f4f8; border-radius: 6px; border-left: 4px solid #3498db;">
                    <strong>Data Limitations:</strong>
                    <ul style="margin: 0.5rem 0 0 0; padding-left: 1.5rem; font-size: 0.9rem;">
                        ${trustScore.data_limitations.map(l => `<li>${l}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
}

/**
 * Generate detailed formula explanation for VirusTotal analysis
 */
function generateVirusTotalFormulaExplanation(trustScore) {
    const components = trustScore.components;
    
    return `
        <h4 style="margin-top: 0; color: #667eea;">📊 How We Calculate the File Security Score</h4>
        <p style="color: #666; margin-bottom: 1.5rem;">
            We look at 5 key factors from VirusTotal to determine if a file is safe. Here's how each factor contributes to the final score:
        </p>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">1. 🔍 Antivirus Detection Results (40 points - Most Important)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we check:</strong> How many antivirus engines flagged this file as dangerous
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• If NO engines detect threats → Full 40 points ✓
                    <br>• Each "malicious" detection counts heavily against the score
                    <br>• "Suspicious" detections count less than malicious, but still matter
                    <br>• More clean scans = higher score
                    <br><br>
                    <strong>Why it matters:</strong> This is the most important indicator. If many antivirus programs flag it, it's likely dangerous.
                </p>
            </div>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">2. ✍️ Digital Signature Check (20 points)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we check:</strong> Does the file have a valid digital signature from its creator?
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• Valid signature (verified by VirusTotal) → 20 points ✓
                    <br>• Invalid or tampered signature → 0 points ✗
                    <br>• No signature or unclear → 10 points
                    <br><br>
                    <strong>Why it matters:</strong> Digital signatures prove the file comes from a legitimate publisher and hasn't been modified.
                </p>
            </div>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">3. 📅 File History (15 points)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we check:</strong> How long has this file been known to VirusTotal?
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• Files known for 30+ days → Full 15 points
                    <br>• Very new files (less than 30 days) → Slightly lower score
                    <br>• Penalty decreases as file gets older
                    <br><br>
                    <strong>Why it matters:</strong> Brand new files have less history. Malware often shows up as new, unknown files.
                </p>
            </div>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">4. 🎯 Threat Identification (15 points)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we check:</strong> Has VirusTotal classified this as a specific type of threat?
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• No threat classification → Full 15 points ✓
                    <br>• Any threat label (trojan, malware, etc.) → 0 points ✗
                    <br><br>
                    <strong>Why it matters:</strong> If VirusTotal identifies it as malware, ransomware, or any threat type, it's dangerous.
                </p>
            </div>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">5. 🏢 Publisher Verification (10 points)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we check:</strong> Is the publisher's digital signature verified?
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• Valid publisher signature → Full 10 points ✓
                    <br>• Invalid signature → 0 points ✗
                    <br>• No signature info → 5 points
                    <br><br>
                    <strong>Why it matters:</strong> Legitimate software publishers sign their files to prove authenticity.
                </p>
            </div>
        </div>
        
        <div style="background: #fff3cd; padding: 1.25rem; border-radius: 6px; border-left: 4px solid #ffc107; margin-top: 1.5rem;">
            <h5 style="margin-top: 0; color: #856404;">⚠️ How We Determine Risk Level</h5>
            <p style="margin: 0; font-size: 0.95rem; line-height: 1.6; color: #856404;">
                <strong>Special Rule:</strong> If even 1 antivirus engine calls it "malicious", we automatically set minimum risk to MEDIUM.<br><br>
                • 10+ malicious detections = 🔴 CRITICAL risk<br>
                • 5-9 malicious detections = 🟠 HIGH risk<br>
                • 1-4 malicious detections = 🟡 MEDIUM risk<br>
                • 0 malicious detections = Score-based (see below)<br><br>
                <strong>If no malicious detections:</strong><br>
                • Score 75-100 = 🟢 LOW risk<br>
                • Score 50-74 = 🟡 MEDIUM risk<br>
                • Score 25-49 = 🟠 HIGH risk<br>
                • Score 0-24 = 🔴 CRITICAL risk
            </p>
        </div>
        
        <div style="background: #d1ecf1; padding: 1.25rem; border-radius: 6px; border-left: 4px solid #17a2b8; margin-top: 1rem;">
            <h5 style="margin-top: 0; color: #0c5460;">💯 Confidence in Our Assessment</h5>
            <p style="margin: 0; font-size: 0.95rem; line-height: 1.6; color: #0c5460;">
                Our confidence depends on how many antivirus engines scanned the file:<br><br>
                • 60+ engines scanned = HIGH confidence ✓✓✓<br>
                • 40-59 engines scanned = MEDIUM confidence ✓✓<br>
                • Less than 40 engines = LOW confidence ✓<br><br>
                <strong>Note:</strong> More scanners = more reliable assessment
            </p>
        </div>
    `;
}

/**
 * Generate detailed formula explanation for standard product/vendor analysis
 */
function generateStandardFormulaExplanation(trustScore) {
    const components = trustScore.components;
    
    return `
        <h4 style="margin-top: 0; color: #667eea;">📊 How We Calculate the Trust Score</h4>
        <p style="color: #666; margin-bottom: 1.5rem;">
            We analyze 3 key security metrics from authoritative sources to calculate product/vendor risk:
        </p>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">1. 🔓 CVSS - Vulnerability Severity (50% weight)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we measure:</strong> Common Vulnerability Scoring System (CVSS) scores from the National Vulnerability Database
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• CVSS scores range from 0-10 (0 = no risk, 10 = critical)
                    <br>• We calculate the average CVSS score across all known CVEs
                    <br>• The average is normalized to 0-1 scale
                    <br>• Higher CVSS = Higher risk to your organization
                    <br>• This metric carries 50% weight in the final calculation
                    <br><br>
                    <strong>Why it matters:</strong> CVSS is the industry-standard metric for vulnerability severity. It tells you how dangerous each security flaw is if exploited.
                </p>
            </div>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">2. 🎯 EPSS - Exploit Probability (40% weight)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we measure:</strong> Exploit Prediction Scoring System from FIRST.org
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• EPSS predicts the probability (0-100%) that a vulnerability will be exploited in the wild within 30 days
                    <br>• We calculate the average EPSS score across all CVEs
                    <br>• Scores are updated daily based on real-world threat intelligence
                    <br>• Higher EPSS = More likely to be actively exploited by attackers
                    <br>• This metric carries 40% weight in the final calculation
                    <br><br>
                    <strong>Why it matters:</strong> Not all vulnerabilities are equally likely to be exploited. EPSS tells you which ones attackers are actually targeting RIGHT NOW.
                </p>
            </div>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">3. ⚠️ KEV - Known Exploited Vulnerabilities (10% weight)</h5>
            <div style="background: #e8f4f8; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 4px solid #3498db;">
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.6;">
                    <strong>What we measure:</strong> CISA Known Exploited Vulnerabilities catalog
                    <br><br>
                    <strong>How it works:</strong>
                    <br>• Binary flag: 0 if no KEVs found, 1 if any KEVs exist
                    <br>• CISA maintains a list of vulnerabilities confirmed to be actively exploited
                    <br>• These are often used in ransomware attacks and major breaches
                    <br>• This metric carries 10% weight in the final calculation
                    <br><br>
                    <strong>Why it matters:</strong> If a vulnerability is on CISA's KEV list, it means hackers are ACTIVELY using it in real attacks. These are the highest priority to patch.
                </p>
            </div>
        </div>
        
        <div style="background: #fff3cd; padding: 1.25rem; border-radius: 6px; border-left: 4px solid #ffc107; margin-top: 1.5rem;">
            <h5 style="margin-top: 0; color: #856404;">⚠️ Final Score Calculation</h5>
            <p style="margin: 0; font-size: 0.95rem; line-height: 1.6; color: #856404;">
                <strong>Formula:</strong><br>
                Risk Score = (0.5 × CVSS/10) + (0.4 × EPSS) + (0.1 × KEV)<br>
                Trust Score = (1 - Risk Score) × 100<br><br>
                <strong>Risk Level Thresholds:</strong><br>
                • Score 75-100 = 🟢 VERY_LOW risk<br>
                • Score 60-74 = 🟡 LOW risk<br>
                • Score 40-59 = 🟠 MEDIUM risk<br>
                • Score 25-39 = 🔴 HIGH risk<br>
                • Score 0-24 = 🔴 CRITICAL risk
            </p>
        </div>
        
        <div style="background: #d1ecf1; padding: 1.25rem; border-radius: 6px; border-left: 4px solid #17a2b8; margin-top: 1rem;">
            <h5 style="margin-top: 0; color: #0c5460;">💯 Confidence in Our Assessment</h5>
            <p style="margin: 0; font-size: 0.95rem; line-height: 1.6; color: #0c5460;">
                Our confidence depends on data completeness:<br><br>
                • HIGH confidence: CVSS data available for most CVEs + EPSS data available<br>
                • MEDIUM confidence: Some CVSS or EPSS data missing<br>
                • LOW confidence: Significant data gaps<br><br>
                <strong>Data sources:</strong> NVD (CVE/CVSS), FIRST.org (EPSS), CISA (KEV catalog)
            </p>
        </div>
    `;
}

function renderSecurityPractices(securityPractices) {
    const isLLMGenerated = securityPractices.data_source === 'llm_generated';
    const hasWarning = securityPractices.data_source_warning;
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🔒 Security Practices</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                <p><strong>Overall Rating:</strong> <span class="badge">${securityPractices.rating.toUpperCase()}</span></p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0;">
                    <div>
                        <strong>Bug Bounty:</strong> ${securityPractices.bug_bounty === true ? '✅ Yes' : securityPractices.bug_bounty === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Disclosure Policy:</strong> ${securityPractices.disclosure_policy === true ? '✅ Yes' : securityPractices.disclosure_policy === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Security Team:</strong> ${securityPractices.security_team_visible === true ? '✅ Visible' : securityPractices.security_team_visible === false ? '❌ Not Visible' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Patch Cadence:</strong> ${securityPractices.patch_cadence}
                    </div>
                </div>
                <p style="margin-top: 1rem;">${securityPractices.summary}</p>
                ${isLLMGenerated && hasWarning ? `
                    <div style="margin-top: 1rem; padding: 0.75rem; background: #fef8e7; border-left: 4px solid #f39c12; border-radius: 4px;">
                        <strong style="color: #f39c12;">⚠️ AI-Generated Analysis</strong>
                        <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: #666;">
                            ${hasWarning}
                        </p>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderIncidents(incidents) {
    if (incidents.count === 0 && incidents.severity === 'none') {
        return '';
    }
    
    const isLLMGenerated = incidents.data_source === 'llm_generated';
    const hasWarning = incidents.data_source_warning;
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>⚠️ Security Incidents & Abuse Signals</h3>
            <div style="background: ${incidents.severity === 'high' || incidents.severity === 'critical' ? '#fee' : '#fef8e7'}; 
                        padding: 1.5rem; border-radius: 8px; border-left: 4px solid ${incidents.severity === 'high' || incidents.severity === 'critical' ? '#c33' : '#f39c12'};">
                <p><strong>Incident Count:</strong> ${incidents.count}</p>
                <p><strong>Severity:</strong> <span class="badge ${incidents.severity}">${incidents.severity.toUpperCase()}</span></p>
                <p><strong>Rating:</strong> ${incidents.rating.toUpperCase()}</p>
                <p style="margin-top: 1rem;">${incidents.summary}</p>
                ${incidents.incidents && incidents.incidents.length > 0 ? `
                    <details style="margin-top: 1rem;">
                        <summary style="cursor: pointer; font-weight: bold;">View Incident Details</summary>
                        <ul style="margin-top: 0.5rem;">
                            ${incidents.incidents.map(inc => `<li>${JSON.stringify(inc)}</li>`).join('')}
                        </ul>
                    </details>
                ` : ''}
                ${isLLMGenerated && hasWarning ? `
                    <div style="margin-top: 1rem; padding: 0.75rem; background: #fff; border-left: 4px solid #f39c12; border-radius: 4px;">
                        <strong style="color: #f39c12;">⚠️ AI-Generated Analysis</strong>
                        <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: #666;">
                            ${hasWarning}
                        </p>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderDataCompliance(dataCompliance) {
    // Debug logging
    console.log('renderDataCompliance called with:', dataCompliance);
    
    // Skip rendering if not applicable (vendor-only assessment)
    if (!dataCompliance || dataCompliance.not_applicable) {
        console.log('Rendering not_applicable view');
        return `
            <div style="margin-bottom: 2rem;">
                <h3>📋 Data Handling & Compliance</h3>
                <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px; text-align: center; color: #666;">
                    <p style="margin: 0;">
                        <em>Not applicable for vendor-only assessments.</em><br>
                        <small>${dataCompliance?.reason || 'Please specify a product for data compliance analysis.'}</small>
                    </p>
                </div>
            </div>
        `;
    }
    
    console.log('Rendering full compliance view');
    const isLLMGenerated = dataCompliance.data_source === 'llm_generated';
    const hasWarning = dataCompliance.data_source_warning;
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>📋 Data Handling & Compliance</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                <p><strong>Compliance Status:</strong> <span class="badge ${dataCompliance.status === 'compliant' ? 'low' : dataCompliance.status === 'partial' ? 'medium' : 'high'}">
                    ${(dataCompliance.status || 'unknown').toUpperCase()}
                </span></p>
                <p><strong>GDPR Compliant:</strong> ${dataCompliance.gdpr_compliant === true ? '✅ Yes' : dataCompliance.gdpr_compliant === false ? '❌ No' : '❓ Unknown'}</p>
                <p><strong>Privacy Rating:</strong> ${(dataCompliance.privacy_rating || 'unknown').toUpperCase()}</p>
                ${dataCompliance.certifications && dataCompliance.certifications.length > 0 ? `
                    <p><strong>Certifications:</strong> ${dataCompliance.certifications.join(', ')}</p>
                ` : ''}
                <p><strong>Data Residency:</strong> ${dataCompliance.data_residency || 'Unknown'}</p>
                <p style="margin-top: 1rem;">${dataCompliance.summary || ''}</p>
                ${isLLMGenerated && hasWarning ? `
                    <div style="margin-top: 1rem; padding: 0.75rem; background: #fef8e7; border-left: 4px solid #f39c12; border-radius: 4px;">
                        <strong style="color: #f39c12;">⚠️ AI-Generated Analysis</strong>
                        <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: #666;">
                            ${hasWarning}
                        </p>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderDeploymentControls(deploymentControls) {
    // Skip rendering if not applicable (vendor-only assessment)
    if (!deploymentControls || deploymentControls.not_applicable) {
        return `
            <div style="margin-bottom: 2rem;">
                <h3>🛠️ Deployment & Admin Controls</h3>
                <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px; text-align: center; color: #666;">
                    <p style="margin: 0;">
                        <em>Not applicable for vendor-only assessments.</em><br>
                        <small>${deploymentControls?.reason || 'Please specify a product for deployment controls analysis.'}</small>
                    </p>
                </div>
            </div>
        `;
    }
    
    const isLLMGenerated = deploymentControls.data_source === 'llm_generated';
    const hasWarning = deploymentControls.data_source_warning;
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🛠️ Deployment & Admin Controls</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                <p><strong>Control Rating:</strong> <span class="badge">${(deploymentControls.control_rating || 'unknown').toUpperCase()}</span></p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0;">
                    <div>
                        <strong>SSO Support:</strong> ${deploymentControls.sso_support === true ? '✅ Yes' : deploymentControls.sso_support === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>MFA Support:</strong> ${deploymentControls.mfa_support === true ? '✅ Yes' : deploymentControls.mfa_support === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>RBAC Available:</strong> ${deploymentControls.rbac_available === true ? '✅ Yes' : deploymentControls.rbac_available === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Audit Logging:</strong> ${deploymentControls.audit_logging === true ? '✅ Yes' : deploymentControls.audit_logging === false ? '❌ No' : '❓ Unknown'}
                    </div>
                </div>
                ${deploymentControls.key_features && deploymentControls.key_features.length > 0 ? `
                    <div style="margin-top: 1rem;">
                        <strong>Key Features:</strong>
                        <ul>
                            ${deploymentControls.key_features.map(f => `<li>${f}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${deploymentControls.limitations && deploymentControls.limitations.length > 0 ? `
                    <div style="margin-top: 1rem;">
                        <strong>Limitations:</strong>
                        <ul>
                            ${deploymentControls.limitations.map(l => `<li>${l}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                <p style="margin-top: 1rem;">${deploymentControls.summary || ''}</p>
                ${isLLMGenerated && hasWarning ? `
                    <div style="margin-top: 1rem; padding: 0.75rem; background: #fef8e7; border-left: 4px solid #f39c12; border-radius: 4px;">
                        <strong style="color: #f39c12;">⚠️ AI-Generated Analysis</strong>
                        <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: #666;">
                            ${hasWarning}
                        </p>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderSecurityPosture(security) {
    const vulnSummary = security.vulnerability_summary || {};
    const dataSource = vulnSummary.data_source;
    const dataSourceNote = vulnSummary.data_source_note;
    const isAPIBased = dataSource === 'api_data_with_llm_analysis';
    const cveTimeline = vulnSummary.cve_timeline || {};
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>Security Posture Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #667eea;">${vulnSummary.total_cves || 0}</div>
                    <div>Total CVEs</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #c33;">${vulnSummary.total_kevs || 0}</div>
                    <div>Known Exploited</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #667eea;">${vulnSummary.trend || 'unknown'}</div>
                    <div>Trend</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #e67e22;">${vulnSummary.exploitation_risk || 'unknown'}</div>
                    <div>Exploitation Risk</div>
                </div>
            </div>
            
            ${isAPIBased && dataSourceNote ? `
                <div style="margin-bottom: 1rem; padding: 0.75rem; background: #e8f5e9; border-left: 4px solid #27ae60; border-radius: 4px;">
                    <strong style="color: #27ae60;">✓ Verified Data Source</strong>
                    <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: #666;">
                        ${dataSourceNote}
                    </p>
                </div>
            ` : ''}
            
            ${Object.keys(cveTimeline).length > 0 ? `
                <details id="cveTimelineDetails" open style="margin-top: 1.5rem; background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <summary style="cursor: pointer; font-weight: bold; font-size: 1.1rem; color: #667eea; margin-bottom: 1rem;">
                        📈 CVE Timeline Analysis (${vulnSummary.total_cves} vulnerabilities across ${Object.keys(cveTimeline).length} years)
                    </summary>
                    <div style="background: white; padding: 1.5rem; border-radius: 6px; margin-top: 1rem;">
                        <p style="color: #666; margin-bottom: 1rem;">
                            This time series chart shows the distribution of discovered vulnerabilities over time, helping identify security trends and patterns.
                        </p>
                        <div style="position: relative; height: 400px;">
                            <canvas id="cveTimelineChart"></canvas>
                        </div>
                    </div>
                </details>
            ` : ''}
            
            ${vulnSummary.critical_findings && vulnSummary.critical_findings.length > 0 ? `
                <div style="background: #fee; padding: 1rem; border-radius: 8px; border-left: 4px solid #c33; margin-top: 1rem;">
                    <h4>⚠️ Critical Findings</h4>
                    <ul>
                        ${vulnSummary.critical_findings.map(f => `<li>${f}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${vulnSummary.key_concerns && vulnSummary.key_concerns.length > 0 ? `
                <div style="margin-top: 1rem;">
                    <h4>Key Concerns</h4>
                    <ul>
                        ${vulnSummary.key_concerns.map(c => `<li>${c}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
}

function renderAlternatives(alternatives) {
    if (!alternatives || alternatives.length === 0) {
        return '';
    }
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🔍 Safer Alternatives</h3>
            <p style="color: #666; margin-bottom: 1rem;">
                Each alternative has been assessed using the same CVSS + EPSS + KEV scoring system. 
                Results are sorted by trust score (highest first).
            </p>
            ${alternatives.map((alt, index) => {
                const trustScore = alt.trust_score || 0;
                const riskLevel = alt.risk_level || 'unknown';
                const assessed = alt.assessed !== false;
                
                // Get risk level color and emoji
                let riskColor, riskEmoji;
                if (riskLevel === 'low') {
                    riskColor = '#28a745';
                    riskEmoji = '✅';
                } else if (riskLevel === 'medium') {
                    riskColor = '#ffc107';
                    riskEmoji = '⚠️';
                } else if (riskLevel === 'high') {
                    riskColor = '#fd7e14';
                    riskEmoji = '⚠️';
                } else if (riskLevel === 'critical') {
                    riskColor = '#dc3545';
                    riskEmoji = '🚨';
                } else {
                    riskColor = '#6c757d';
                    riskEmoji = '❓';
                }
                
                return `
                    <div style="background: #fff; border: 2px solid ${index === 0 ? '#28a745' : '#e9ecef'}; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        ${index === 0 ? '<div style="background: #28a745; color: white; display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; margin-bottom: 0.5rem; font-size: 0.85rem; font-weight: bold;">🏆 BEST ALTERNATIVE</div>' : ''}
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                            <div>
                                <h4 style="margin: 0 0 0.25rem 0; color: #2c3e50;">${alt.product_name}</h4>
                                <div style="color: #666; font-size: 0.9rem;">${alt.vendor || 'Unknown Vendor'}</div>
                            </div>
                            ${assessed ? `
                                <div style="text-align: right;">
                                    <div style="font-size: 2rem; font-weight: bold; color: ${riskColor};">${trustScore.toFixed(1)}</div>
                                    <div style="font-size: 0.85rem; color: ${riskColor}; font-weight: 600;">${riskEmoji} ${riskLevel.toUpperCase()}</div>
                                </div>
                            ` : '<div style="color: #6c757d; font-style: italic;">Not assessed</div>'}
                        </div>
                        
                        <p style="margin-bottom: 1rem; line-height: 1.6;">${alt.rationale}</p>
                        
                        ${assessed && alt.scoring_breakdown ? `
                            <div style="background: #f8f9fa; padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                                <strong style="font-size: 0.9rem; color: #495057;">Security Metrics:</strong>
                                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; margin-top: 0.5rem;">
                                    ${alt.scoring_breakdown.cvss_risk !== undefined ? `
                                        <div>
                                            <div style="font-size: 0.85rem; color: #666;">🔓 CVSS Risk (50%)</div>
                                            <div style="font-weight: bold; color: #dc3545;">${(alt.scoring_breakdown.cvss_risk * 100).toFixed(1)}%</div>
                                        </div>
                                    ` : ''}
                                    ${alt.scoring_breakdown.epss_risk !== undefined ? `
                                        <div>
                                            <div style="font-size: 0.85rem; color: #666;">🎯 EPSS Risk (40%)</div>
                                            <div style="font-weight: bold; color: #fd7e14;">${(alt.scoring_breakdown.epss_risk * 100).toFixed(1)}%</div>
                                        </div>
                                    ` : ''}
                                    ${alt.scoring_breakdown.kev_risk !== undefined ? `
                                        <div>
                                            <div style="font-size: 0.85rem; color: #666;">⚠️ KEV Risk (10%)</div>
                                            <div style="font-weight: bold; color: #ffc107;">${(alt.scoring_breakdown.kev_risk * 100).toFixed(1)}%</div>
                                        </div>
                                    ` : ''}
                                </div>
                                <div style="margin-top: 0.75rem; font-size: 0.85rem; color: #666;">
                                    📊 ${alt.cve_count || 0} CVEs found | ${alt.kev_count || 0} Known Exploited Vulnerabilities
                                </div>
                            </div>
                        ` : ''}
                        
                        ${alt.security_advantages && alt.security_advantages.length > 0 ? `
                            <div>
                                <strong style="font-size: 0.9rem; color: #495057;">Key Advantages:</strong>
                                <ul style="margin: 0.5rem 0 0 1.5rem; line-height: 1.8;">
                                    ${alt.security_advantages.map(adv => `<li>${adv}</li>`).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                `;
            }).join('')}
        </div>
    `;
}


function renderMetadata(assessment) {
    return `
        <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; font-size: 0.9rem; color: #666;">
            <strong>Sources:</strong>
            ${assessment.sources.map(s => s.name).join(', ')}
            <br>
            <strong>Generated:</strong> ${new Date(assessment.metadata.timestamp).toLocaleString()}
            ${assessment._cached ? `<br><strong>⚡ From Cache:</strong> ${new Date(assessment._cache_timestamp).toLocaleString()}` : ''}
            ${assessment.metadata.evidence_hash ? `<br><strong>Evidence Hash:</strong> <code style="font-size: 0.8rem;">${assessment.metadata.evidence_hash.substring(0, 16)}...</code>` : ''}
            ${assessment._analysis_mode ? `<br><strong>Analysis Mode:</strong> ${assessment._analysis_mode}` : ''}
        </div>
    `;
}

/**
 * VirusTotal-specific rendering functions
 */

function renderVirusTotalDetectionDetails(virustotal) {
    if (!virustotal) return '';
    
    const detection = virustotal.detection;
    const fileInfo = virustotal.file_info;
    
    // Calculate threat level
    const malicious = detection.malicious || 0;
    const suspicious = detection.suspicious || 0;
    const totalDetections = malicious + suspicious;
    
    let threatLevel = 'Clean';
    let threatColor = '#27ae60';
    let threatIcon = '✅';
    
    if (malicious > 0) {
        threatLevel = 'Malicious';
        threatColor = '#c33';
        threatIcon = '🚨';
    } else if (suspicious > 0) {
        threatLevel = 'Suspicious';
        threatColor = '#f39c12';
        threatIcon = '⚠️';
    }
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🔍 Detection Analysis</h3>
            
            <div style="background: ${threatColor}; color: white; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">
                <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                    <span style="font-size: 3rem;">${threatIcon}</span>
                    <div>
                        <strong style="font-size: 1.5rem; display: block;">${threatLevel}</strong>
                        <span style="font-size: 2rem; font-weight: bold;">${detection.ratio}</span>
                    </div>
                </div>
            </div>
            
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                <h4 style="margin-top: 0;">Detection Breakdown</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                    <div style="text-align: center; padding: 1rem; background: white; border-radius: 6px;">
                        <div style="font-size: 2rem; font-weight: bold; color: #c33;">
                            ${detection.malicious}
                        </div>
                        <div style="color: #666; font-size: 0.9rem;">Malicious</div>
                    </div>
                    <div style="text-align: center; padding: 1rem; background: white; border-radius: 6px;">
                        <div style="font-size: 2rem; font-weight: bold; color: #f39c12;">
                            ${detection.suspicious}
                        </div>
                        <div style="color: #666; font-size: 0.9rem;">Suspicious</div>
                    </div>
                    <div style="text-align: center; padding: 1rem; background: white; border-radius: 6px;">
                        <div style="font-size: 2rem; font-weight: bold; color: #27ae60;">
                            ${detection.undetected}
                        </div>
                        <div style="color: #666; font-size: 0.9rem;">Undetected</div>
                    </div>
                    <div style="text-align: center; padding: 1rem; background: white; border-radius: 6px;">
                        <div style="font-size: 2rem; font-weight: bold; color: #3498db;">
                            ${detection.harmless}
                        </div>
                        <div style="color: #666; font-size: 0.9rem;">Harmless</div>
                    </div>
                </div>
                
                <div style="margin-top: 1.5rem; padding: 1rem; background: white; border-radius: 6px;">
                    <h4 style="margin-top: 0;">File Information</h4>
                    <div style="display: grid; grid-template-columns: auto 1fr; gap: 0.5rem 1rem; font-size: 0.9rem;">
                        <strong>Primary Name:</strong>
                        <span>${fileInfo.primary_name || 'Unknown'}</span>
                        
                        <strong>File Type:</strong>
                        <span>${fileInfo.type || 'Unknown'}</span>
                        
                        <strong>File Size:</strong>
                        <span>${fileInfo.size ? formatBytes(fileInfo.size) : 'Unknown'}</span>
                        
                        ${fileInfo.last_analysis_date ? `
                            <strong>Last Scanned:</strong>
                            <span>${new Date(fileInfo.last_analysis_date).toLocaleDateString()}</span>
                        ` : ''}
                        
                        ${fileInfo.names && fileInfo.names.length > 1 ? `
                            <strong>Known Names:</strong>
                            <span>${fileInfo.names.slice(0, 3).join(', ')}${fileInfo.names.length > 3 ? '...' : ''}</span>
                        ` : ''}
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderVirusTotalThreatAnalysis(virustotal) {
    if (!virustotal) return '';
    
    const signature = virustotal.signature;
    const threatClass = virustotal.threat_classification;
    const tags = virustotal.tags || [];
    const hashes = virustotal.file_hash;
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🎯 Threat Intelligence</h3>
            
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                ${signature ? `
                    <div style="background: white; padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                        <h4 style="margin-top: 0;">📝 Digital Signature</h4>
                        <div style="display: grid; grid-template-columns: auto 1fr; gap: 0.5rem 1rem; font-size: 0.9rem;">
                            ${signature.verified ? `
                                <strong>Verification:</strong>
                                <span>${signature.verified.includes('valid') || signature.verified.includes('Valid') ? '✅' : '❌'} ${signature.verified}</span>
                            ` : ''}
                            
                            ${signature.product ? `
                                <strong>Product:</strong>
                                <span>${signature.product}</span>
                            ` : ''}
                            
                            ${signature.signers ? `
                                <strong>Signers:</strong>
                                <span>${signature.signers}</span>
                            ` : ''}
                            
                            ${signature.copyright ? `
                                <strong>Copyright:</strong>
                                <span>${signature.copyright}</span>
                            ` : ''}
                        </div>
                    </div>
                ` : ''}
                
                ${threatClass && threatClass.suggested_threat_label ? `
                    <div style="background: white; padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                        <h4 style="margin-top: 0;">🚨 Threat Classification</h4>
                        <div style="font-size: 1.1rem; padding: 0.5rem; background: #fee; border-radius: 4px; border-left: 4px solid #c33;">
                            <strong>${threatClass.suggested_threat_label}</strong>
                        </div>
                    </div>
                ` : ''}
                
                ${tags.length > 0 ? `
                    <div style="background: white; padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                        <h4 style="margin-top: 0;">🏷️ Tags & Indicators</h4>
                        <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                            ${tags.map(tag => `
                                <span style="background: #667eea; color: white; padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.85rem;">
                                    ${tag}
                                </span>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
                
                <div style="background: white; padding: 1rem; border-radius: 6px;">
                    <h4 style="margin-top: 0;">🔐 File Hashes</h4>
                    <div style="font-family: monospace; font-size: 0.85rem; word-break: break-all;">
                        ${hashes.sha256 ? `<div style="margin-bottom: 0.5rem;"><strong>SHA-256:</strong> ${hashes.sha256}</div>` : ''}
                        ${hashes.sha1 ? `<div style="margin-bottom: 0.5rem;"><strong>SHA-1:</strong> ${hashes.sha1}</div>` : ''}
                        ${hashes.md5 ? `<div style="margin-bottom: 0.5rem;"><strong>MD5:</strong> ${hashes.md5}</div>` : ''}
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Create CVE Timeline Chart using Chart.js
 * @param {Object} cveTimeline - Object mapping years to CVE counts
 */
function createCVETimelineChart(cveTimeline) {
    console.log('createCVETimelineChart called with:', cveTimeline);
    console.log('Number of years in timeline:', Object.keys(cveTimeline).length);
    console.log('Years range:', Object.keys(cveTimeline).sort());
    
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded!');
        return;
    }
    
    const canvas = document.getElementById('cveTimelineChart');
    if (!canvas) {
        console.error('Canvas element #cveTimelineChart not found in DOM');
        return;
    }
    
    console.log('Canvas element found:', canvas);
    
    // Destroy existing chart if it exists
    const existingChart = Chart.getChart(canvas);
    if (existingChart) {
        console.log('Destroying existing chart');
        existingChart.destroy();
    }
    
    // Prepare data
    const years = Object.keys(cveTimeline).sort();
    const counts = years.map(year => cveTimeline[year]);
    
    console.log('Chart data - Years:', years);
    console.log('Chart data - Counts:', counts);
    
    if (years.length === 0 || counts.length === 0) {
        console.warn('No data to display in chart');
        return;
    }
    
    // Find max value for scaling
    const maxCount = Math.max(...counts);
    
    // Create gradient for line fill
    const ctx = canvas.getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(102, 126, 234, 0.5)');
    gradient.addColorStop(1, 'rgba(118, 75, 162, 0.05)');
    
    console.log('Creating Chart.js instance...');
    
    // Create chart
    try {
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: years,
                datasets: [{
                    label: 'Number of CVEs',
                    data: counts,
                    backgroundColor: gradient,
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: 'rgba(102, 126, 234, 1)',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    pointHoverBackgroundColor: 'rgba(118, 75, 162, 1)',
                    pointHoverBorderColor: '#fff',
                    pointHoverBorderWidth: 3,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            font: {
                                size: 14,
                                weight: 'bold'
                            },
                            color: '#333'
                        }
                    },
                    title: {
                        display: true,
                        text: 'CVE Discovery Time Series',
                        font: {
                            size: 16,
                            weight: 'bold'
                        },
                        color: '#667eea',
                        padding: {
                            top: 10,
                            bottom: 20
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        borderColor: '#667eea',
                        borderWidth: 2,
                        padding: 12,
                        displayColors: false,
                        callbacks: {
                            title: function(tooltipItems) {
                                return 'Year ' + tooltipItems[0].label;
                            },
                            label: function(context) {
                                const count = context.parsed.y;
                                const total = counts.reduce((a, b) => a + b, 0);
                                const percentage = ((count / total) * 100).toFixed(1);
                                return [
                                    `CVEs Discovered: ${count}`,
                                    `Percentage of Total: ${percentage}%`
                                ];
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: Math.ceil(maxCount / 10),
                            font: {
                                size: 12
                            },
                            color: '#666'
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)',
                            drawBorder: false
                        },
                        title: {
                            display: true,
                            text: 'Number of Vulnerabilities',
                            font: {
                                size: 13,
                                weight: 'bold'
                            },
                            color: '#666'
                        }
                    },
                    x: {
                        ticks: {
                            font: {
                                size: 12
                            },
                            color: '#666',
                            maxRotation: 45,
                            minRotation: 0
                        },
                        grid: {
                            display: false,
                            drawBorder: false
                        },
                        title: {
                            display: true,
                            text: 'Year',
                            font: {
                                size: 13,
                                weight: 'bold'
                            },
                            color: '#666'
                        }
                    }
                },
                animation: {
                    duration: 1000,
                    easing: 'easeInOutQuart'
                }
            }
        });
        
        console.log('Chart created successfully:', chart);
    } catch (error) {
        console.error('Error creating chart:', error);
    }
}

/**
 * Render Security Ecosystem Graph Card
 * @returns {string} HTML for the graph container
 */
function renderSecurityEcosystemGraphCard() {
    return `
        <div class="card" style="margin-top: 2rem;">
            <h3 style="display: flex; align-items: center; gap: 0.5rem;">
                <span style="font-size: 1.5rem;">🕸️</span>
                Security Ecosystem Graph
            </h3>
            <p style="color: #666; margin-bottom: 1.5rem; line-height: 1.6;">
                Interactive knowledge graph showing relationships between product, vendor, vulnerabilities, 
                alternatives, and data sources. Click nodes for details, hover to highlight connections.
            </p>
            
            <!-- Graph Controls -->
            <div id="graphControls" style="margin-bottom: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                <button onclick="filterGraphBySeverity('all')" 
                        style="padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
                    ✓ Show All CVEs
                </button>
                <button onclick="filterGraphBySeverity('critical_high')" 
                        style="padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
                    ⚠️ Critical + High Only
                </button>
                <button onclick="filterGraphBySeverity('critical')" 
                        style="padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
                    🔴 Critical Only
                </button>
                <button onclick="centerGraphOnProduct()" 
                        style="padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
                    🎯 Re-center
                </button>
                <button onclick="toggleGraphPhysics()" 
                        style="padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
                    ⚡ Toggle Physics
                </button>
                <button onclick="exportGraphAsPNG()" 
                        style="padding: 0.5rem 1rem; border: 1px solid #667eea; background: #667eea; color: white; border-radius: 4px; cursor: pointer; font-size: 0.9rem; font-weight: 500;">
                    💾 Export PNG
                </button>
            </div>
            
            <!-- Graph Container -->
            <div id="securityGraph" 
                 style="width: 100%; height: 600px; border: 2px solid #e1e8ed; border-radius: 8px; background: #fafbfc;">
                <div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #999;">
                    <div style="text-align: center;">
                        <div style="font-size: 3rem; margin-bottom: 1rem;">🔄</div>
                        <div>Loading security ecosystem graph...</div>
                    </div>
                </div>
            </div>
            
            <!-- Legend -->
            <div id="graphLegend" style="margin-top: 1.5rem; padding: 1.5rem; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 8px; border: 1px solid #dee2e6;">
                <div style="font-weight: 700; margin-bottom: 1.2rem; font-size: 1.1rem; color: #2c3e50;">
                    📊 Graph Legend & Guide
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; font-size: 0.95rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <span style="display: inline-block; width: 24px; height: 24px; background: #1E88E5; border: 3px solid #1565C0; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></span>
                        <span><strong>🎯 Product</strong> - Main item being assessed</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <span style="display: inline-block; width: 24px; height: 24px; background: #43A047; border: 3px solid #2E7D32; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></span>
                        <span><strong>🏢 Vendor</strong> - Company/developer</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <span style="display: inline-block; width: 24px; height: 24px; background: #D32F2F; border: 3px solid #B71C1C; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></span>
                        <span><strong>🔴 Critical CVE</strong> - Severe vulnerability</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <span style="display: inline-block; width: 24px; height: 24px; background: #FF6F00; border: 3px solid #E65100; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></span>
                        <span><strong>🟠 High CVE</strong> - Significant risk</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <span style="display: inline-block; width: 24px; height: 24px; background: #C2185B; border: 3px solid #880E4F; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></span>
                        <span><strong>⚠️ KEV</strong> - Actively exploited</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <span style="display: inline-block; width: 24px; height: 24px; background: #8E24AA; border: 3px solid #6A1B9A; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></span>
                        <span><strong>💡 Alternative</strong> - Safer option</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <span style="display: inline-block; width: 20px; height: 20px; background: #00897B; border: 3px solid #00695C; border-radius: 3px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></span>
                        <span><strong>📊 Data Source</strong> - Information provider</span>
                    </div>
                </div>
                <div style="margin-top: 1.2rem; padding: 1rem; background: #e3f2fd; border-left: 4px solid #1E88E5; border-radius: 4px; font-size: 0.9rem; line-height: 1.6;">
                    <strong>💡 How to use:</strong><br>
                    • <strong>Hover</strong> over nodes to highlight connections<br>
                    • <strong>Click</strong> CVE nodes to open NVD database in new tab<br>
                    • <strong>Drag</strong> to pan, <strong>scroll</strong> to zoom<br>
                    • <strong>Solid lines</strong> show direct relationships<br>
                    • <strong>Dashed lines</strong> indicate alternatives or data sources<br>
                    • <strong>Line thickness</strong> represents relationship strength or severity
                </div>
            </div>
        </div>
    `;
}

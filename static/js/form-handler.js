/**
 * Form Handler Module
 * Handles form submission and assessment initiation
 */

document.addEventListener('DOMContentLoaded', function() {
    const assessmentForm = document.getElementById('assessmentForm');
    
    if (assessmentForm) {
        assessmentForm.addEventListener('submit', handleFormSubmit);
    }
});

/**
 * Handle assessment form submission
 * @param {Event} e - Form submit event
 */
async function handleFormSubmit(e) {
    e.preventDefault();
    
    const inputText = document.getElementById('input_text').value.trim();
    const useCache = document.getElementById('use_cache').checked;
    const submitBtn = document.getElementById('submitBtn');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const errorMsg = document.getElementById('errorMsg');
    const progressMessage = document.getElementById('progressMessage');
    const multiAgentProgress = document.getElementById('multiAgentProgress');
    
    // Clear previous results
    results.style.display = 'none';
    errorMsg.innerHTML = '';
    
    // Reset progress stages
    resetProgressStages();
    
    // Show loading
    loading.classList.add('active');
    submitBtn.disabled = true;
    progressMessage.textContent = 'Starting assessment...';
    
    // Generate session ID
    const sessionId = Date.now().toString();
    
    try {
        // Start assessment
        const response = await fetch('/assess', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                input_text: inputText,
                use_cache: useCache,
                session_id: sessionId
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Assessment failed');
        }
        
        if (data.success && data.session_id) {
            // Check if result was cached
            if (data.cached && data.assessment) {
                // Display cached result immediately
                progressMessage.textContent = '✓ Retrieved from cache (instant)';
                
                // Hide loading and show results section
                loading.classList.remove('active');
                submitBtn.disabled = false;
                
                const resultsDiv = document.getElementById('results');
                const resultsContent = document.getElementById('resultsContent');
                
                resultsDiv.style.display = 'block';
                
                // Display the assessment first (this will set innerHTML)
                displayAssessment(data.assessment);
                
                // Then prepend the cache banner at the top
                const cacheBanner = document.createElement('div');
                cacheBanner.style.cssText = 'background: #e3f2fd; border-left: 4px solid #2196f3; padding: 1rem; margin-bottom: 1.5rem; border-radius: 4px;';
                cacheBanner.innerHTML = `
                    <strong>⚡ Cached Result</strong><br>
                    <small style="color: #666;">
                        This assessment was retrieved from cache (generated within the last 24 hours). 
                        <a href="javascript:location.reload()" style="color: #2196f3;">Refresh to generate new</a>
                    </small>
                `;
                resultsContent.insertBefore(cacheBanner, resultsContent.firstChild);
            } else {
                // Show multi-agent progress if enabled
                multiAgentProgress.style.display = 'block';
                
                // Connect to progress stream
                connectProgressStream(sessionId, inputText, useCache);
            }
        }
        
    } catch (error) {
        errorMsg.innerHTML = `<div class="error">❌ ${error.message}</div>`;
        loading.classList.remove('active');
        submitBtn.disabled = false;
    }
}

/**
 * Reset all progress stage indicators to initial state
 */
function resetProgressStages() {
    const stages = document.querySelectorAll('.progress-stage');
    stages.forEach(stage => {
        stage.className = 'progress-stage';
        const statusElement = stage.querySelector('.progress-status');
        if (statusElement) {
            statusElement.textContent = 'pending';
        }
        
        // Reset icon based on stage
        const iconElement = stage.querySelector('.progress-icon');
        const stageType = stage.getAttribute('data-stage');
        if (iconElement) {
            switch(stageType) {
                case 'preparation':
                    iconElement.textContent = '⏳';
                    break;
                case 'research':
                    iconElement.textContent = '🔍';
                    break;
                case 'verification':
                    iconElement.textContent = '✅';
                    break;
                case 'synthesis':
                    iconElement.textContent = '📝';
                    break;
            }
        }
    });
}

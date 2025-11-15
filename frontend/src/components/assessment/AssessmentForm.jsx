import { useState } from 'react';
import { assessmentAPI } from '../../services/api';

function AssessmentForm({ onStart, onComplete, onError }) {
  const [inputText, setInputText] = useState('');
  const [useCache, setUseCache] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!inputText.trim()) {
      onError({ message: 'Please enter a product name, vendor, SHA1 hash, or URL' });
      return;
    }

    setIsSubmitting(true);
    const sessionId = Date.now().toString();

    try {
      // Submit assessment
      const result = await assessmentAPI.submitAssessment({
        input_text: inputText.trim(),
        use_cache: useCache,
        session_id: sessionId,
      });

      // Check if result contains error
      if (result.error) {
        onError(result);
        setIsSubmitting(false);
        return;
      }

      // Check if setup is required (for SHA1)
      if (result.setup_required) {
        onError({
          message: result.error,
          setupRequired: true,
          ...result,
        });
        setIsSubmitting(false);
        return;
      }

      // Success - notify parent that assessment has started
      // Don't call onComplete here - let ProgressTracker handle it
      onStart(sessionId);
      setInputText(''); // Clear form
      setIsSubmitting(false);
    } catch (error) {
      console.error('Assessment error:', error);
      onError(error);
      setIsSubmitting(false);
    }
  };

  const handleExampleClick = (example) => {
    setInputText(example);
  };

  return (
    <div className="max-w-2xl mx-auto mb-8">
      <div className="bg-card border border-border rounded-2xl p-8 shadow-lg">
        <h2 className="text-2xl font-bold mb-2">Start Security Assessment</h2>
        <p className="text-muted-foreground mb-6">
          Enter a product name, vendor, URL, or SHA1 hash to analyze its security posture
        </p>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="input-text" className="block text-sm font-medium mb-2">
              Product or Vendor Information
            </label>
            <textarea
              id="input-text"
              className="w-full px-4 py-3 bg-input-background border border-input rounded-lg focus:outline-none focus:ring-2 focus:ring-ring resize-none"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="e.g., Google Chrome, Microsoft, https://example.com, or SHA1 hash"
              rows={4}
              disabled={isSubmitting}
            />
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="use-cache"
              checked={useCache}
              onChange={(e) => setUseCache(e.target.checked)}
              disabled={isSubmitting}
              className="w-4 h-4 rounded border-border"
            />
            <label htmlFor="use-cache" className="text-sm text-muted-foreground cursor-pointer">
              Use cached results (faster, may be slightly outdated)
            </label>
          </div>

          <button
            type="submit"
            className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 bg-violet-600 text-white rounded-lg hover:bg-violet-700 transition-colors font-medium text-lg disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={isSubmitting || !inputText.trim()}
          >
            {isSubmitting ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white"></div>
                Analyzing...
              </>
            ) : (
              <>
                Generate Assessment
              </>
            )}
          </button>
        </form>

        {/* Example Inputs */}
        <div className="mt-6 pt-6 border-t border-border">
          <h4 className="text-sm font-medium mb-3 text-muted-foreground">Quick Examples:</h4>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium disabled:opacity-50"
              onClick={() => handleExampleClick('Google Chrome')}
              disabled={isSubmitting}
            >
              Google Chrome
            </button>
            <button
              type="button"
              className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium disabled:opacity-50"
              onClick={() => handleExampleClick('Microsoft')}
              disabled={isSubmitting}
            >
              Microsoft
            </button>
            <button
              type="button"
              className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium disabled:opacity-50"
              onClick={() => handleExampleClick('Apache HTTP Server')}
              disabled={isSubmitting}
            >
              Apache HTTP Server
            </button>
            <button
              type="button"
              className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors text-sm font-medium disabled:opacity-50"
              onClick={() => handleExampleClick('https://github.com')}
              disabled={isSubmitting}
            >
              GitHub URL
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AssessmentForm;

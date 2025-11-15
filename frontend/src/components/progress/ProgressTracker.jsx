import { useEffect, useState } from 'react';

function ProgressTracker({ sessionId, onComplete, onError }) {
  const [progress, setProgress] = useState([]);
  const [currentStage, setCurrentStage] = useState(null);
  const [isComplete, setIsComplete] = useState(false);

  useEffect(() => {
    if (!sessionId) return;

    // Use relative URL - Vite proxy will handle it in development
    const eventSource = new EventSource(`/api/stream/${sessionId}`);

    eventSource.onopen = () => {
      console.log('EventSource connection opened for session:', sessionId);
    };

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('Progress update:', data);

        // Add to progress list
        setProgress(prev => [...prev, data]);
        setCurrentStage(data);

        // Check if complete
        if (data.stage === 'complete' && data.result) {
          setIsComplete(true);
          onComplete(data.result);
          eventSource.close();
        }
      } catch (err) {
        console.error('Failed to parse progress event:', err, event.data);
      }
    };

    eventSource.onerror = (error) => {
      console.error('EventSource error:', error);
      eventSource.close();
      onError({
        message: 'Connection lost while processing assessment. Please try again.'
      });
    };

    // Cleanup
    return () => {
      console.log('Closing EventSource for session:', sessionId);
      eventSource.close();
    };
  }, [sessionId, onComplete, onError]);

  const stages = [
    { key: 'initialization', label: 'Initializing Assessment', icon: '🚀' },
    { key: 'data_gathering', label: 'Gathering Product Data', icon: '📊' },
    { key: 'entity_resolution', label: 'Resolving Entity', icon: '🔍' },
    { key: 'security_data', label: 'Fetching Security Data', icon: '🛡️' },
    { key: 'preparation', label: 'Preparing Analysis', icon: '⚙️' },
    { key: 'research', label: 'Research Agent Analysis', icon: '🔬' },
    { key: 'verification', label: 'Verification Agent Review', icon: '✓' },
    { key: 'synthesis', label: 'Synthesis Agent Integration', icon: '�' },
  ];

  const getCurrentStageIndex = () => {
    if (!currentStage) return -1;
    const stage = currentStage.stage;
    const index = stages.findIndex(s => s.key === stage);
    
    // If exact match not found, try to match partial stages
    if (index === -1) {
      if (stage.includes('initialization') || stage.includes('start')) return 0;
      if (stage.includes('data') || stage.includes('gathering')) return 1;
      if (stage.includes('entity') || stage.includes('resolution')) return 2;
      if (stage.includes('security') || stage.includes('cve')) return 3;
      if (stage.includes('preparation') || stage.includes('preparing')) return 4;
      if (stage.includes('research')) return 5;
      if (stage.includes('verification') || stage.includes('verif')) return 6;
      if (stage.includes('synthesis') || stage.includes('synth')) return 7;
    }
    
    return index;
  };

  const currentStageIndex = getCurrentStageIndex();
  const progressPercentage = isComplete ? 100 : currentStageIndex >= 0 ? ((currentStageIndex + 1) / stages.length) * 100 : 5;

  if (!sessionId) {
    return (
      <div className="max-w-3xl mx-auto my-6">
        <div className="bg-gray-800 border border-gray-600 rounded-xl p-4 shadow-lg text-center">
          <p className="text-gray-400">No active session</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto my-6">
      <div className="bg-gray-800 border border-gray-600 rounded-xl p-4 shadow-lg">
        <h3 className="text-lg font-bold text-white mb-2">Assessment in Progress</h3>
        <p className="text-sm text-gray-400 mb-4">
          {currentStage?.details || 'Analyzing security posture and gathering data...'}
        </p>

        {/* Progress Bar */}
        <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden mb-1">
          <div 
            className="h-full bg-blue-500 transition-all duration-500 ease-out rounded-full"
            style={{ width: `${progressPercentage}%` }}
          />
        </div>
        <div className="text-right text-xs font-semibold text-blue-400 mb-4">
          {Math.round(progressPercentage)}%
        </div>

        {/* Stage List */}
        <div className="space-y-2">
          {stages.map((stage, index) => {
            const isActive = index === currentStageIndex;
            const isCompleted = index < currentStageIndex || isComplete;
            const isCurrent = index === currentStageIndex && !isComplete;

            return (
              <div 
                key={stage.key}
                className={`flex items-start gap-2 p-2 rounded-lg transition-all ${
                  isActive ? 'bg-blue-900/30 border-l-4 border-blue-500' : 
                  isCompleted ? 'bg-green-900/30 border-l-4 border-green-500' : 
                  'bg-gray-700/30 border-l-4 border-transparent'
                }`}
              >
                <div className={`shrink-0 w-7 h-7 rounded-full flex items-center justify-center font-bold text-xs ${
                  isCompleted ? 'bg-green-500 text-white' : 
                  isActive ? 'bg-blue-500 text-white' : 
                  'bg-gray-700 text-gray-400'
                }`}>
                  {isCompleted ? '✓' : stage.icon || (index + 1)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className={`text-sm font-semibold ${
                    isActive || isCompleted ? 'text-white' : 'text-gray-400'
                  }`}>
                    {stage.label}
                  </div>
                  {isCurrent && currentStage?.details && (
                    <div className="text-xs text-gray-400 mt-1">
                      {currentStage.details}
                    </div>
                  )}
                </div>
                {isCurrent && (
                  <div className="shrink-0">
                    <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Progress Messages */}
        {progress.length > 0 && (
          <details className="mt-4 group">
            <summary className="cursor-pointer list-none text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors">
              View Detailed Progress ({progress.length} updates)
              <span className="ml-2 inline-block group-open:rotate-180 transition-transform">▼</span>
            </summary>
            <div className="mt-3 space-y-1 max-h-48 overflow-y-auto bg-gray-900/50 rounded-lg p-3">
              {progress.map((item, index) => (
                <div key={index} className="text-xs border-l-2 border-blue-500/30 pl-2 py-1">
                  <span className="text-gray-500 font-mono">
                    {new Date(item.timestamp || Date.now()).toLocaleTimeString()}
                  </span>
                  <span className="font-semibold text-gray-300 mx-2">{item.stage}:</span>
                  <span className="text-gray-400">{item.details || item.message}</span>
                </div>
              ))}
            </div>
          </details>
        )}

        {isComplete && (
          <div className="mt-4 p-3 bg-green-900/40 border border-green-600 rounded-lg flex items-center gap-3">
            <div className="w-7 h-7 bg-green-500 text-white rounded-full flex items-center justify-center font-bold text-sm">
              ✓
            </div>
            <span className="font-semibold text-green-400">
              Assessment completed successfully!
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

export default ProgressTracker;

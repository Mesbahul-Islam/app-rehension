function ExpandableCard({ title, badge, isOpen, onToggle, children }) {
  return (
    <div className={`bg-card border border-border rounded-xl shadow-sm hover:shadow-md transition-shadow ${isOpen ? '' : 'h-fit'}`}>
      <button
        onClick={onToggle}
        className={`w-full p-4 flex items-center justify-between text-left group hover:bg-secondary/50 transition-colors ${isOpen ? 'rounded-t-xl' : 'rounded-xl'}`}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-foreground">{title}</span>
          {badge !== undefined && badge !== null && (
            <span className="px-2 py-1 bg-primary/20 text-primary text-xs font-bold rounded-full">
              {badge}
            </span>
          )}
        </div>
        <svg 
          className={`w-5 h-5 text-muted-foreground transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none" 
          stroke="currentColor" 
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isOpen && (
        <div className="p-4 border-t border-border">
          {children}
        </div>
      )}
    </div>
  );
}

export default ExpandableCard;

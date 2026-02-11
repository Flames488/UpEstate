// components/AppLoading.tsx
'use client';

import { useEffect, useState } from 'react';

export default function AppLoading() {
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    // This will be replaced by actual app mounting logic
    const timer = setTimeout(() => {
      setIsVisible(false);
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

  if (!isVisible) return null;

  return (
    <div id="app-loading" className="app-loading-state">
      <div className="loading-spinner" role="status" aria-label="Loading application">
        <svg viewBox="0 0 50 50" className="spinner-svg">
          <circle cx="25" cy="25" r="20" fill="none" strokeWidth="5"></circle>
        </svg>
        <span className="sr-only">Loading application...</span>
      </div>
      <noscript>
        <div className="noscript-warning">
          <h1>JavaScript Required</h1>
          <p>This application requires JavaScript to function properly. Please enable JavaScript in your browser settings.</p>
        </div>
      </noscript>
    </div>
  );
}
// components/PerformanceMonitoring.tsx
'use client';

import { useEffect } from 'react';

declare global {
  interface Window {
    ENV?: {
      isProduction: boolean;
      isDevelopment: boolean;
      isMobile: boolean;
    };
    FEATURES?: Record<string, boolean>;
    appStartTime?: number;
    analytics?: {
      track: (event: string, data: any) => void;
    };
  }
}

export default function PerformanceMonitoring() {
  useEffect(() => {
    // Set environment flags
    window.ENV = {
      isProduction: window.location.hostname !== 'localhost' && !window.location.hostname.includes('dev'),
      isDevelopment: window.location.hostname === 'localhost' || window.location.hostname.includes('dev'),
      isMobile: /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent),
    };
    
    // Feature detection
    window.FEATURES = {
      serviceWorker: 'serviceWorker' in navigator,
      webShare: 'share' in navigator,
      clipboard: 'clipboard' in navigator && 'writeText' in navigator.clipboard,
      indexedDB: 'indexedDB' in window,
      webGL: (() => {
        try {
          return !!window.WebGLRenderingContext && !!document.createElement('canvas').getContext('webgl');
        } catch (e) {
          return false;
        }
      })(),
    };

    // Performance monitoring
    if ('performance' in window) {
      window.appStartTime = performance.now();
      
      const reportWebVitals = (metric: any) => {
        console.log('[Web Vitals]', metric);
        if (window.analytics) {
          window.analytics.track('web_vital', metric);
        }
      };
      
      // LCP tracking
      new PerformanceObserver((entryList) => {
        const entries = entryList.getEntries();
        const lastEntry = entries[entries.length - 1];
        reportWebVitals({
          name: 'LCP',
          value: lastEntry.startTime,
          rating: lastEntry.startTime < 2500 ? 'good' : lastEntry.startTime < 4000 ? 'needs-improvement' : 'poor'
        });
      }).observe({ type: 'largest-contentful-paint', buffered: true });
      
      // CLS tracking
      let clsValue = 0;
      new PerformanceObserver((entryList) => {
        for (const entry of entryList.getEntries()) {
          if (!(entry as any).hadRecentInput) {
            clsValue += entry.value;
            reportWebVitals({
              name: 'CLS',
              value: clsValue,
              rating: clsValue < 0.1 ? 'good' : clsValue < 0.25 ? 'needs-improvement' : 'poor'
            });
          }
        }
      }).observe({ type: 'layout-shift', buffered: true });
    }

    // Handle page visibility
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        window.dispatchEvent(new CustomEvent('app-visible'));
      } else {
        window.dispatchEvent(new CustomEvent('app-hidden'));
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    // Global error handler
    const handleError = (event: ErrorEvent) => {
      console.error('Global error caught:', event.error);
      
      const errorDisplay = document.getElementById('global-error');
      if (errorDisplay) {
        errorDisplay.style.display = 'block';
      }
    };

    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.error('Unhandled promise rejection:', event.reason);
    };

    window.addEventListener('error', handleError);
    window.addEventListener('unhandledrejection', handleUnhandledRejection);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('error', handleError);
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, []);

  return null;
}
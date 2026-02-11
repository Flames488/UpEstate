// components/ClientInitializers.tsx
'use client';

import { useEffect } from 'react';

export default function ClientInitializers() {
  useEffect(() => {
    // Service Worker Registration
    if ('serviceWorker' in navigator && window.ENV?.isProduction) {
      const registerServiceWorker = async () => {
        try {
          const registration = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
          console.log('ServiceWorker registered:', registration);
          (window as any).serviceWorkerRegistration = registration;
          
          // Check for updates
          registration.addEventListener('updatefound', () => {
            const newWorker = registration.installing;
            console.log('ServiceWorker update found');
            
            newWorker?.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                window.dispatchEvent(new CustomEvent('swUpdateAvailable'));
              }
            });
          });
        } catch (error) {
          console.error('ServiceWorker registration failed:', error);
        }
      };

      window.addEventListener('load', registerServiceWorker);
      return () => window.removeEventListener('load', registerServiceWorker);
    }
  }, []);

  useEffect(() => {
    // Performance markers
    if (typeof window !== 'undefined') {
      performance.mark('app-html-parsed');
      
      const handleLoad = () => {
        performance.mark('app-window-loaded');
        
        if (window.appStartTime) {
          const tti = performance.now() - window.appStartTime;
          console.log(`Time to Interactive: ${tti.toFixed(2)}ms`);
          
          if (window.analytics) {
            window.analytics.track('performance_tti', { value: tti });
          }
        }
      };
      
      window.addEventListener('load', handleLoad);
      return () => window.removeEventListener('load', handleLoad);
    }
  }, []);

  return null;
}
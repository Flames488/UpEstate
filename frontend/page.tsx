// app/page.tsx
import { Metadata, Viewport } from 'next';
import { Suspense } from 'react';
import AppLoading from '@/components/AppLoading';
import ErrorBoundary from '@/components/ErrorBoundary';
import PerformanceMonitoring from '@/components/PerformanceMonitoring';
import ClientInitializers from '@/components/ClientInitializers';
import './globals.css';

// Metadata
export const metadata: Metadata = {
  title: {
    template: '%s | App',
    default: 'App',
  },
  description: 'A modern web application with advanced capabilities',
  keywords: ['web', 'app', 'application', 'modern', 'advanced'],
  authors: [{ name: 'Your Company' }],
  robots: 'index, follow',
  
  // Open Graph
  openGraph: {
    title: 'Advanced Application',
    description: 'A cutting-edge web application',
    type: 'website',
    url: 'https://yourapp.com',
    images: [
      {
        url: '/social-preview.jpg',
        alt: 'Application Preview',
      },
    ],
  },
  
  // Twitter
  twitter: {
    card: 'summary_large_image',
    creator: '@yourhandle',
  },
  
  // Icons
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: 'any' },
      { url: '/icon.svg', type: 'image/svg+xml' },
    ],
    apple: '/apple-touch-icon.png',
    other: [
      {
        rel: 'mask-icon',
        url: '/safari-pinned-tab.svg',
        color: '#1a1a1a',
      },
    ],
  },
  
  // Canonical
  alternates: {
    canonical: 'https://yourapp.com',
  },
  
  // PWA
  manifest: '/app.webmanifest',
  appleWebApp: {
    capable: true,
    title: 'App',
    startupImage: [
      {
        url: '/splash-iphone.png',
        media: '(device-width: 320px) and (device-height: 568px) and (-webkit-device-pixel-ratio: 2) and (orientation: portrait)',
      },
    ],
  },
};

// Viewport settings
export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#1a1a1a',
  viewportFit: 'cover',
};

// Security headers are configured in next.config.js or middleware
// Performance monitoring will be handled client-side

export default function Home() {
  return (
    <>
      {/* Preconnect for external domains */}
      <link rel="preconnect" href="https://api.yourapp.com" crossOrigin="anonymous" />
      <link rel="preconnect" href="https://cdn.yourapp.com" crossOrigin="anonymous" />
      <link rel="dns-prefetch" href="https://api.yourapp.com" />
      <link rel="dns-prefetch" href="https://cdn.yourapp.com" />
      
      {/* Error Boundary */}
      <ErrorBoundary>
        {/* Main Content */}
        <main id="root" role="main" aria-live="polite">
          <Suspense fallback={<AppLoading />}>
            {/* Your main application content will go here */}
            <div className="app-content">
              <h1 className="sr-only">Application Content</h1>
              {/* Application components will be rendered here */}
            </div>
          </Suspense>
        </main>
      </ErrorBoundary>
      
      {/* Client-side initializers */}
      <ClientInitializers />
      
      {/* Performance monitoring */}
      <PerformanceMonitoring />
    </>
  );
}
// components/ErrorBoundary.tsx
'use client';

import React, { Component, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    // Send to error tracking service
    if (typeof window !== 'undefined' && (window as any).errorTracking) {
      (window as any).errorTracking.captureException(error, {
        context: { 
          url: window.location.href, 
          userAgent: navigator.userAgent,
          componentStack: errorInfo.componentStack 
        }
      });
    }
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div id="global-error" className="global-error-boundary" role="alert" aria-live="assertive">
          <div className="error-boundary">
            <h2>Something went wrong</h2>
            <p>Our team has been notified.</p>
            <button onClick={this.handleReload}>Reload Application</button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
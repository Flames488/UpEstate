import { api } from './api';
import { BillingError } from '../errors/billing-error';
import { logger } from '../utils/logger';

export interface CheckoutResponse {
  checkout_url: string;
  session_id?: string;
  expires_at?: string;
}

export interface SubscriptionStatus {
  isActive: boolean;
  plan?: string;
  validUntil?: Date;
  features?: string[];
}

export class BillingService {
  /**
   * Initiates a subscription checkout process
   * @throws {BillingError} When checkout fails
   */
  static async initiateCheckout(planId?: string): Promise<void> {
    try {
      const payload = planId ? { plan_id: planId } : undefined;
      const { data } = await api.post<CheckoutResponse>(
        '/billing/checkout',
        payload,
        {
          timeout: 10000,
          headers: { 'Idempotency-Key': crypto.randomUUID() },
        }
      );

      if (!data.checkout_url) {
        throw new BillingError('No checkout URL received');
      }

      // Store session ID for potential recovery
      if (data.session_id) {
        sessionStorage.setItem('checkout_session_id', data.session_id);
      }

      // Use replace instead of href to prevent back navigation issues
      window.location.replace(data.checkout_url);
    } catch (error) {
      logger.error('Checkout initiation failed', { error, planId });
      throw new BillingError(
        error instanceof Error ? error.message : 'Checkout failed',
        { cause: error }
      );
    }
  }

  /**
   * Validates subscription status
   */
  static async validateSubscription(): Promise<SubscriptionStatus> {
    try {
      const { data } = await api.get<SubscriptionStatus>(
        '/billing/subscription/status'
      );
      return data;
    } catch (error) {
      logger.warn('Subscription validation failed', { error });
      throw new BillingError('Unable to verify subscription status');
    }
  }

  /**
   * Gracefully redirects to upgrade page
   */
  static redirectToUpgrade(reason?: string): void {
    const params = new URLSearchParams();
    if (reason) params.set('reason', reason);
    params.set('return_to', window.location.pathname);
    
    window.location.href = `/upgrade?${params.toString()}`;
  }
}

// For backward compatibility
export const subscribe = BillingService.initiateCheckout;
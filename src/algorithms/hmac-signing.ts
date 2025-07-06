import { createHmac, timingSafeEqual } from 'crypto';
import canonicalize from 'canonicalize';
import { SigningAlgorithm } from '../interfaces/crypto';
import { JsonPayload } from '../types/crypto';

/**
 * Configuration options for HMAC signing
 */
export interface HmacSigningOptions {
  /** The secret key for HMAC signing */
  secret: string;
  /** The hash algorithm to use (default: 'sha256') */
  algorithm?: string;
}

/**
 * HMAC-based signing algorithm implementation.
 * Uses RFC 8785 JSON canonicalization for consistent serialization.
 */
export class HmacSigning implements SigningAlgorithm {
  private readonly secret: string;
  private readonly algorithm: string;

  constructor(options: HmacSigningOptions) {
    this.secret = options.secret;
    this.algorithm = options.algorithm || 'sha256';
  }

  /**
   * Signs data using HMAC with the configured algorithm.
   * Uses RFC 8785 canonicalization for consistent serialization.
   * @param data - The data to sign
   * @returns The signature as a hexadecimal string
   * @throws Error if signing fails
   */
  sign(data: JsonPayload): string {
    try {
      // Use RFC 8785 canonicalization for consistent, crypto-safe serialization
      const canonicalData = canonicalize(data);

      if (!canonicalData) {
        throw new Error('Failed to canonicalize data');
      }

      const hmac = createHmac(this.algorithm, this.secret);
      hmac.update(canonicalData, 'utf8');
      return hmac.digest('hex');
    } catch (error) {
      throw new Error(
        `Signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Verifies a signature against the provided data.
   * @param data - The data to verify
   * @param signature - The signature to verify against
   * @returns True if the signature is valid
   */
  verify(data: JsonPayload, signature: string): boolean {
    try {
      if (signature.length === 0) {
        return false;
      }

      const expectedSignature = this.sign(data);

      if (signature.length !== expectedSignature.length) {
        return false;
      }

      const signatureBuffer = Buffer.from(signature, 'hex');
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');

      if (signatureBuffer.length !== expectedBuffer.length) {
        return false;
      }

      return timingSafeEqual(signatureBuffer, expectedBuffer);
    } catch (_error) {
      return false;
    }
  }
}

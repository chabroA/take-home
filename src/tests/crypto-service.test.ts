import { CryptoService } from '../services/crypto-service';
import { Base64Encryption } from '../algorithms/base64-encryption';
import { HmacSigning } from '../algorithms/hmac-signing';
import * as fc from 'fast-check';

describe('CryptoService', () => {
  let cryptoService: CryptoService;

  beforeEach(() => {
    const encryptionAlgorithm = new Base64Encryption();
    const signingAlgorithm = new HmacSigning({
      secret: 'riot-take-home-secret',
    });
    cryptoService = new CryptoService(encryptionAlgorithm, signingAlgorithm);
  });

  describe('Signing and Verification', () => {
    it('should sign a payload and verify it', () => {
      const payload = {
        message: 'Hello World',
        timestamp: 1616161616,
      };

      const { signature } = cryptoService.signPayload(payload);
      const isValid = cryptoService.verifySignature(payload, signature);

      expect(isValid).toBe(true);
    });

    it('should produce the same signature regardless of property order', () => {
      const payload1 = {
        message: 'Hello World',
        timestamp: 1616161616,
      };

      const payload2 = {
        timestamp: 1616161616,
        message: 'Hello World',
      };

      const { signature: signature1 } = cryptoService.signPayload(payload1);
      const { signature: signature2 } = cryptoService.signPayload(payload2);

      expect(signature1).toBe(signature2);
    });

    it('should reject invalid signatures', () => {
      const payload = {
        message: 'Hello World',
        timestamp: 1616161616,
      };

      const tamperedPayload = {
        message: 'Goodbye World',
        timestamp: 1616161616,
      };

      const { signature } = cryptoService.signPayload(payload);
      const isValid = cryptoService.verifySignature(tamperedPayload, signature);

      expect(isValid).toBe(false);
    });
  });

  describe('Property-Based Testing - Consistency Requirements', () => {
    describe('Sign/Verify Consistency', () => {
      it('sign followed by verify should always return true for any valid JSON object', () => {
        fc.assert(
          fc.property(
            fc.record({
              message: fc.string(),
              timestamp: fc.integer(),
              data: fc.record({
                id: fc.integer(),
                value: fc.string(),
                active: fc.boolean(),
              }),
              tags: fc.array(fc.string(), { minLength: 0, maxLength: 5 }),
              metadata: fc.record({
                count: fc.integer(),
                score: fc.float().filter(n => !isNaN(n) && isFinite(n)),
                name: fc.string(),
                enabled: fc.boolean(),
              }),
            }),
            payload => {
              const { signature } = cryptoService.signPayload(payload);
              const isValid = cryptoService.verifySignature(payload, signature);

              expect(isValid).toBe(true);
            }
          ),
          { numRuns: 100 }
        );
      });

      it('signature should be consistent regardless of property order', () => {
        fc.assert(
          fc.property(
            fc.record({
              prop1: fc.string(),
              prop2: fc.integer(),
              prop3: fc.boolean(),
              prop4: fc.record({
                nested1: fc.string(),
                nested2: fc.integer(),
              }),
            }),
            originalPayload => {
              // Create the same payload with shuffled property order
              const keys = Object.keys(originalPayload) as Array<
                keyof typeof originalPayload
              >;
              const shuffledPayload: any = {};

              keys.reverse().forEach(key => {
                shuffledPayload[key] = originalPayload[key];
              });

              const { signature: signature1 } =
                cryptoService.signPayload(originalPayload);
              const { signature: signature2 } =
                cryptoService.signPayload(shuffledPayload);

              expect(signature1).toBe(signature2);

              // Both signatures should verify against both payloads
              expect(
                cryptoService.verifySignature(originalPayload, signature1)
              ).toBe(true);
              expect(
                cryptoService.verifySignature(shuffledPayload, signature1)
              ).toBe(true);
              expect(
                cryptoService.verifySignature(originalPayload, signature2)
              ).toBe(true);
              expect(
                cryptoService.verifySignature(shuffledPayload, signature2)
              ).toBe(true);
            }
          ),
          { numRuns: 50 }
        );
      });

      it('verification should fail for tampered payloads', () => {
        fc.assert(
          fc.property(
            fc.record({
              message: fc.string({ minLength: 1 }),
              value: fc.integer(),
              flag: fc.boolean(),
            }),
            fc.string({ minLength: 1 }),
            (originalPayload, tamperValue) => {
              // Skip if tamper value is the same as original message
              fc.pre(tamperValue !== originalPayload.message);

              const { signature } = cryptoService.signPayload(originalPayload);

              // Create tampered payload
              const tamperedPayload = {
                ...originalPayload,
                message: tamperValue,
              };

              const isValidOriginal = cryptoService.verifySignature(
                originalPayload,
                signature
              );
              const isValidTampered = cryptoService.verifySignature(
                tamperedPayload,
                signature
              );

              expect(isValidOriginal).toBe(true);
              expect(isValidTampered).toBe(false);
            }
          ),
          { numRuns: 50 }
        );
      });
    });
  });
});

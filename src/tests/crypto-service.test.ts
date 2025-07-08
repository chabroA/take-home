import * as fc from 'fast-check';
import { createTestCryptoService } from './test-config';
import { CryptoService } from '../services/crypto-service';

describe('CryptoService', () => {
  let cryptoService: CryptoService;

  beforeAll(() => {
    cryptoService = createTestCryptoService();
  });

  describe('Property-Based Testing - Consistency Requirements', () => {
    // Property-based tests to verify the consistency requirements:
    // 1. encrypt followed by decrypt should return the original payload
    // 2. sign followed by verify should always return true
    //
    // Note: These tests exclude edge case value -0 which is not supported by
    // the current implementation as it is treated similarly to 0.
    describe('Encrypt/Decrypt Consistency', () => {
      it('encrypt followed by decrypt should preserve original payload', () => {
        fc.assert(
          fc.property(
            fc.record({
              message: fc.string(),
              timestamp: fc.integer().filter(n => !Object.is(n, -0)),
              data: fc.record({
                id: fc.integer().filter(n => !Object.is(n, -0)),
                value: fc.string(),
                active: fc.boolean(),
              }),
              tags: fc.array(fc.string(), { minLength: 0, maxLength: 5 }),
              metadata: fc.record({
                count: fc.integer().filter(n => !Object.is(n, -0)),
                score: fc
                  .float()
                  .filter(n => !isNaN(n) && isFinite(n) && !Object.is(n, -0)),
                name: fc.string(),
                enabled: fc.boolean(),
              }),
            }),
            originalPayload => {
              const encrypted = cryptoService.encryptPayload(originalPayload);
              const decrypted = cryptoService.decryptPayload(encrypted);

              expect(decrypted).toEqual(originalPayload);
            }
          ),
          { numRuns: 100 }
        );
      });
    });

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
              // Create the same payload with different property order
              const shuffledPayload: typeof originalPayload = {
                prop4: originalPayload.prop4,
                prop1: originalPayload.prop1,
                prop3: originalPayload.prop3,
                prop2: originalPayload.prop2,
              };

              // Verify they have the same content (property order doesn't matter for equality)
              expect(shuffledPayload).toEqual(originalPayload);

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

    describe('Combined Operations Consistency', () => {
      it('encrypt -> sign -> verify -> decrypt should preserve original data', () => {
        fc.assert(
          fc.property(
            fc.record({
              username: fc.constantFrom(
                'john_doe',
                'jane_smith',
                'alice_johnson',
                'bob_wilson'
              ),
              userId: fc.integer({ min: 1, max: 1000000 }),
              profile: fc.record({
                email: fc.emailAddress(),
                age: fc.integer({ min: 18, max: 100 }),
                role: fc.constantFrom('admin', 'user', 'guest'),
              }),
              timestamp: fc.integer({ min: 1000000000, max: 2000000000 }),
            }),
            originalPayload => {
              // 1. Encrypt the payload
              const encrypted = cryptoService.encryptPayload(originalPayload);

              // 2. Sign the encrypted payload
              const { signature } = cryptoService.signPayload(encrypted);

              // 3. Verify the signature
              const isValid = cryptoService.verifySignature(
                encrypted,
                signature
              );
              expect(isValid).toBe(true);

              // 4. Decrypt back to original
              const decrypted = cryptoService.decryptPayload(encrypted);

              // 5. Verify we get back the original payload
              expect(decrypted).toEqual(originalPayload);
            }
          ),
          { numRuns: 30 }
        );
      });

      it('sign -> encrypt -> decrypt -> verify should maintain signature validity', () => {
        fc.assert(
          fc.property(
            fc.record({
              message: fc.constantFrom(
                'Hello World',
                'Test Message',
                'API Response',
                'User Data'
              ),
              timestamp: fc.integer({ min: 1000000000, max: 2000000000 }),
              metadata: fc.record({
                source: fc.constantFrom('api', 'web', 'mobile'),
                version: fc.integer({ min: 1, max: 10 }),
              }),
            }),
            originalPayload => {
              // 1. Sign the original payload
              const { signature } = cryptoService.signPayload(originalPayload);

              // 2. Create a payload with signature
              const payloadWithSignature = { ...originalPayload, signature };

              // 3. Encrypt the payload with signature
              const encrypted =
                cryptoService.encryptPayload(payloadWithSignature);

              // 4. Decrypt to get back the payload with signature
              const decrypted = cryptoService.decryptPayload(encrypted);

              // 5. Extract the signature and verify it against the original data
              const { signature: extractedSignature, ...dataWithoutSignature } =
                decrypted;

              // Ensure signature is a string
              expect(typeof extractedSignature).toBe('string');

              const isValid = cryptoService.verifySignature(
                dataWithoutSignature,
                extractedSignature as string
              );

              expect(isValid).toBe(true);
              expect(dataWithoutSignature).toEqual(originalPayload);
            }
          ),
          { numRuns: 30 }
        );
      });
    });
  });
});

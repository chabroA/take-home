import { FastifyInstance } from 'fastify';
import { createTestServer } from './test-config';

describe('API Integration Tests', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = createTestServer();
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  describe('POST /encrypt', () => {
    it('should encrypt a JSON payload', async () => {
      const payload = {
        name: 'John Doe',
        age: 30,
        contact: {
          email: 'john@example.com',
          phone: '123-456-7890',
        },
      };

      const response = await server.inject({
        method: 'POST',
        url: '/encrypt',
        payload: payload,
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.name).toBe('Sm9obiBEb2U=');
      expect(body.age).toBe('MzA=');
      expect(body.contact).toBe(
        'eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9'
      );
    });

    it('should return 400 for invalid payload', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/encrypt',
        payload: 'invalid json',
        headers: {
          'content-type': 'application/json',
        },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('POST /decrypt', () => {
    it('should decrypt a JSON payload', async () => {
      const encryptedPayload = {
        name: 'Sm9obiBEb2U=',
        age: 'MzA=',
        contact:
          'eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9',
      };

      const response = await server.inject({
        method: 'POST',
        url: '/decrypt',
        payload: encryptedPayload,
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.name).toBe('John Doe');
      expect(body.age).toBe(30);
      expect(body.contact).toEqual({
        email: 'john@example.com',
        phone: '123-456-7890',
      });
    });

    it('should handle mixed encrypted and unencrypted data', async () => {
      const mixedPayload = {
        name: 'Sm9obiBEb2U=',
        age: 'MzA=',
        birth_date: '1998-11-19',
        not_encrypted: 'blue',
      };

      const response = await server.inject({
        method: 'POST',
        url: '/decrypt',
        payload: mixedPayload,
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.name).toBe('John Doe');
      expect(body.age).toBe(30);
      expect(body.birth_date).toBe('1998-11-19');
      expect(body.not_encrypted).toBe('blue');
    });
  });

  describe('POST /sign', () => {
    it('should sign a JSON payload', async () => {
      const payload = {
        message: 'Hello World',
        timestamp: 1616161616,
      };

      const response = await server.inject({
        method: 'POST',
        url: '/sign',
        payload: payload,
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.signature).toBeDefined();
      expect(typeof body.signature).toBe('string');
      expect(body.signature).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce consistent signatures regardless of property order', async () => {
      const payload1 = { message: 'Hello World', timestamp: 1616161616 };
      const payload2 = { timestamp: 1616161616, message: 'Hello World' };

      const response1 = await server.inject({
        method: 'POST',
        url: '/sign',
        payload: payload1,
      });

      const response2 = await server.inject({
        method: 'POST',
        url: '/sign',
        payload: payload2,
      });

      const body1 = JSON.parse(response1.payload);
      const body2 = JSON.parse(response2.payload);
      expect(body1.signature).toBe(body2.signature);
    });
  });

  describe('POST /verify', () => {
    it('should verify a valid signature', async () => {
      const payload = {
        message: 'Hello World',
        timestamp: 1616161616,
      };

      // First, get the signature
      const signResponse = await server.inject({
        method: 'POST',
        url: '/sign',
        payload: payload,
      });

      const signBody = JSON.parse(signResponse.payload);

      // Then verify it
      const verifyResponse = await server.inject({
        method: 'POST',
        url: '/verify',
        payload: {
          signature: signBody.signature,
          data: payload,
        },
      });

      expect(verifyResponse.statusCode).toBe(204);
    });

    it('should reject an invalid signature', async () => {
      const payload = {
        message: 'Hello World',
        timestamp: 1616161616,
      };

      const tamperedPayload = {
        message: 'Goodbye World',
        timestamp: 1616161616,
      };

      // First, get the signature for original payload
      const signResponse = await server.inject({
        method: 'POST',
        url: '/sign',
        payload: payload,
      });

      const signBody = JSON.parse(signResponse.payload);

      // Then try to verify with tampered data
      const verifyResponse = await server.inject({
        method: 'POST',
        url: '/verify',
        payload: {
          signature: signBody.signature,
          data: tamperedPayload,
        },
      });

      expect(verifyResponse.statusCode).toBe(400);
    });

    it('should return 400 for missing signature or data', async () => {
      const response1 = await server.inject({
        method: 'POST',
        url: '/verify',
        payload: { signature: 'test' },
      });

      const response2 = await server.inject({
        method: 'POST',
        url: '/verify',
        payload: { data: { test: 'data' } },
      });

      expect(response1.statusCode).toBe(400);
      expect(response2.statusCode).toBe(400);
    });
  });

  // Minimal consistency tests - just verify the API contracts work end-to-end
  describe('API Consistency', () => {
    it('should support encrypt/decrypt round-trip via API', async () => {
      const originalPayload = { name: 'Test User', id: 123 };

      // Encrypt
      const encryptResponse = await server.inject({
        method: 'POST',
        url: '/encrypt',
        payload: originalPayload,
      });

      expect(encryptResponse.statusCode).toBe(200);
      const encryptedPayload = JSON.parse(encryptResponse.payload);

      // Decrypt
      const decryptResponse = await server.inject({
        method: 'POST',
        url: '/decrypt',
        payload: encryptedPayload,
      });

      expect(decryptResponse.statusCode).toBe(200);
      const decryptedPayload = JSON.parse(decryptResponse.payload);
      expect(decryptedPayload).toEqual(originalPayload);
    });

    it('should support sign/verify round-trip via API', async () => {
      const originalPayload = { message: 'Test', timestamp: 1234567890 };

      // Sign
      const signResponse = await server.inject({
        method: 'POST',
        url: '/sign',
        payload: originalPayload,
      });

      expect(signResponse.statusCode).toBe(200);
      const { signature } = JSON.parse(signResponse.payload);

      // Verify
      const verifyResponse = await server.inject({
        method: 'POST',
        url: '/verify',
        payload: { signature, data: originalPayload },
      });

      expect(verifyResponse.statusCode).toBe(204);
    });
  });
});

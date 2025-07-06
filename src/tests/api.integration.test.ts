import server from '../server';

describe('API Integration Tests', () => {
  beforeAll(async () => {
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
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

  describe('API Consistency', () => {
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

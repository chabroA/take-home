import { FastifyRequest, FastifyReply } from 'fastify';
import { CryptoService } from '../services/crypto-service';

export class CryptoController {
  constructor(private cryptoService: CryptoService) {}

  encrypt = async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    try {
      const payload = request.body;

      if (!payload || typeof payload !== 'object') {
        reply.status(400).send({ error: 'Invalid JSON payload' });
        return;
      }

      const encrypted = this.cryptoService.encryptPayload(payload);
      reply.send(encrypted);
    } catch (error) {
      console.error(error);
      reply.status(500).send({ error: 'Internal server error' });
    }
  };

  decrypt = async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    try {
      const payload = request.body;

      if (!payload || typeof payload !== 'object') {
        reply.status(400).send({ error: 'Invalid JSON payload' });
        return;
      }

      const decrypted = this.cryptoService.decryptPayload(payload);
      reply.send(decrypted);
    } catch (error) {
      console.error(error);
      reply.status(500).send({ error: 'Internal server error' });
    }
  };

  sign = async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    try {
      const payload = request.body;

      if (!payload || typeof payload !== 'object') {
        reply.status(400).send({ error: 'Invalid JSON payload' });
        return;
      }

      const signature = this.cryptoService.signPayload(payload);
      reply.send(signature);
    } catch (error) {
      console.error(error);
      reply.status(500).send({ error: 'Internal server error' });
    }
  };

  verify = async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    try {
      const body = request.body as { signature?: string; data?: any };
      const { signature, data } = body;

      if (!signature || !data) {
        reply.status(400).send({ error: 'Missing signature or data' });
        return;
      }

      const isValid = this.cryptoService.verifySignature(data, signature);

      if (isValid) {
        reply.status(204).send();
      } else {
        reply.status(400).send({ error: 'Invalid signature' });
      }
    } catch (error) {
      console.error(error);
      reply.status(500).send({ error: 'Internal server error' });
    }
  };
}

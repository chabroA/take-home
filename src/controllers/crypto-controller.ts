import { FastifyRequest, FastifyReply } from 'fastify';
import { CryptoService } from '../services/crypto-service';
import { isJsonPayload, isSignedPayload } from '../types/crypto';

export class CryptoController {
  constructor(private cryptoService: CryptoService) {}

  encrypt = async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    try {
      const payload = request.body;

      if (!isJsonPayload(payload)) {
        reply
          .status(400)
          .send({ error: 'Invalid JSON payload - must be an object' });
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

      if (!isJsonPayload(payload)) {
        reply
          .status(400)
          .send({ error: 'Invalid JSON payload - must be an object' });
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

      if (!isJsonPayload(payload)) {
        reply
          .status(400)
          .send({ error: 'Invalid JSON payload - must be an object' });
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
      const body = request.body;

      if (!isSignedPayload(body)) {
        reply.status(400).send({
          error: 'Invalid payload - must contain signature and data properties',
        });
        return;
      }

      const { signature, data } = body;
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

import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';
import { CryptoController } from '../controllers/crypto-controller';

async function cryptoRoutes(
  fastify: FastifyInstance,
  options: FastifyPluginOptions & { cryptoController: CryptoController }
) {
  const { cryptoController } = options;

  fastify.post('/encrypt', cryptoController.encrypt);
  fastify.post('/decrypt', cryptoController.decrypt);
  fastify.post('/sign', cryptoController.sign);
  fastify.post('/verify', cryptoController.verify);
}

export default fp(cryptoRoutes);

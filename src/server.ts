import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import { CryptoService } from './services/crypto-service';
import { CryptoController } from './controllers/crypto-controller';
import cryptoRoutes from './routes/crypto-routes';
import { EncryptionAlgorithm, SigningAlgorithm } from './interfaces/crypto';

export function createServer({
  encryptionAlgorithm,
  signingAlgorithm,
}: {
  encryptionAlgorithm: EncryptionAlgorithm;
  signingAlgorithm: SigningAlgorithm;
}): FastifyInstance {
  const server = Fastify({
    logger: { level: 'error' },
  });

  // Register CORS plugin only in non-production environments
  if (process.env.NODE_ENV !== 'production') {
    server.register(cors, {
      origin: true,
    });
  }

  const cryptoService = new CryptoService(
    encryptionAlgorithm,
    signingAlgorithm
  );

  const cryptoController = new CryptoController(cryptoService);

  server.register(cryptoRoutes, { cryptoController });

  return server;
}

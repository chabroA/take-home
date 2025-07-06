import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import { CryptoService } from './services/crypto-service';
import { CryptoController } from './controllers/crypto-controller';
import { Base64Encryption } from './algorithms/base64-encryption';
import { HmacSigning } from './algorithms/hmac-signing';
import cryptoRoutes from './routes/crypto-routes';

if (!process.env.HMAC_SECRET) {
  console.error('Error: HMAC_SECRET environment variable is required');
  process.exit(1);
}

const server = Fastify({
  logger: { level: 'error' },
});

server.register(cors, {
  origin: true,
});

const encryptionAlgorithm = new Base64Encryption();
const signingAlgorithm = new HmacSigning({ secret: process.env.HMAC_SECRET });

const cryptoService = new CryptoService(encryptionAlgorithm, signingAlgorithm);

const cryptoController = new CryptoController(cryptoService);

server.register(cryptoRoutes, { cryptoController });

export default server;

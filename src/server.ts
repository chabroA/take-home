import Fastify from 'fastify';
import cors from '@fastify/cors';
import { CryptoService } from './services/crypto-service';
import { CryptoController } from './controllers/crypto-controller';
import { Base64Encryption } from './algorithms/base64-encryption';
import { HmacSigning } from './algorithms/hmac-signing';
import cryptoRoutes from './routes/crypto-routes';

const server = Fastify({
  logger: { level: 'error' },
});

server.register(cors, {
  origin: true,
});

const encryptionAlgorithm = new Base64Encryption();
const signingAlgorithm = new HmacSigning();

const cryptoService = new CryptoService(encryptionAlgorithm, signingAlgorithm);

const cryptoController = new CryptoController(cryptoService);

server.register(cryptoRoutes, { cryptoController });

export default server;

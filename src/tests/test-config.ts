import { createServer } from '../server';
import { Base64Encryption } from '../algorithms/base64-encryption';
import { HmacSigning } from '../algorithms/hmac-signing';
import { CryptoService } from '../services/crypto-service';

export function createTestServer() {
  return createServer({
    encryptionAlgorithm: new Base64Encryption(),
    signingAlgorithm: new HmacSigning(),
  });
}

export function createTestCryptoService() {
  return new CryptoService(new Base64Encryption(), new HmacSigning());
}

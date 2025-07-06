import '@dotenvx/dotenvx/config';
import { createServer } from './server';
import { Base64Encryption } from './algorithms/base64-encryption';
import { HmacSigning } from './algorithms/hmac-signing';

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

const server = createServer({
  encryptionAlgorithm: new Base64Encryption(),
  signingAlgorithm: new HmacSigning(),
});

const start = async () => {
  try {
    await server.listen({ port: Number(PORT), host: HOST });
    console.log(`Server is running on ${HOST}:${PORT}`);
    console.log(`Available endpoints:`);
    console.log(`  POST /encrypt - Encrypt JSON payload`);
    console.log(`  POST /decrypt - Decrypt JSON payload`);
    console.log(`  POST /sign - Sign JSON payload`);
    console.log(`  POST /verify - Verify signature`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();

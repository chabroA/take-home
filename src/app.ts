import server from './server';

const PORT = 3000;
const HOST = '0.0.0.0';

const start = async () => {
  try {
    await server.listen({ port: PORT, host: HOST });
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

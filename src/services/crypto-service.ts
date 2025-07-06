import { EncryptionAlgorithm, SigningAlgorithm } from '../interfaces/crypto';

export class CryptoService {
  constructor(
    private encryptionAlgorithm: EncryptionAlgorithm,
    private signingAlgorithm: SigningAlgorithm
  ) {}

  encryptPayload(payload: any): any {
    const result: any = {};

    for (const [key, value] of Object.entries(payload)) {
      if (typeof value === 'object' && value !== null) {
        // For objects, stringify and then encrypt
        result[key] = this.encryptionAlgorithm.encrypt(JSON.stringify(value));
      } else {
        // For primitive values, convert to string and encrypt
        result[key] = this.encryptionAlgorithm.encrypt(String(value));
      }
    }

    return result;
  }

  decryptPayload(payload: any): any {
    const result: any = {};

    for (const [key, value] of Object.entries(payload)) {
      if (typeof value === 'string') {
        const decrypted = this.encryptionAlgorithm.decrypt(value);

        // Try to parse as JSON first (for objects)
        try {
          result[key] = JSON.parse(decrypted);
        } catch {
          // If JSON parsing fails, try to convert to number if it's a numeric string
          const numValue = Number(decrypted);
          if (
            !isNaN(numValue) &&
            isFinite(numValue) &&
            String(numValue) === decrypted
          ) {
            result[key] = numValue;
          } else {
            result[key] = decrypted;
          }
        }
      } else {
        // Keep the original value if it's not encrypted or can't be decrypted
        result[key] = value;
      }
    }

    return result;
  }

  signPayload(payload: any): { signature: string } {
    const signature = this.signingAlgorithm.sign(payload);
    return { signature };
  }

  verifySignature(data: any, signature: string): boolean {
    return this.signingAlgorithm.verify(data, signature);
  }
}

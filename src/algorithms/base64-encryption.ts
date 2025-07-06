import { EncryptionAlgorithm } from '../interfaces/crypto';

export class Base64Encryption implements EncryptionAlgorithm {
  encrypt(data: string): string {
    if (data.length === 0) {
      return data;
    }

    return Buffer.from(data, 'utf8').toString('base64');
  }

  decrypt(data: string): string {
    if (data.length === 0) {
      return data;
    }

    try {
      const decrypted = Buffer.from(data, 'base64').toString('utf8');

      // Check if the decrypted string is valid base64
      // by encrypting it and comparing the result with the original data
      // Slower than naive regex check, but more robust
      const encrypted = this.encrypt(decrypted);

      if (encrypted === data) {
        return decrypted;
      }

      return data;
    } catch (_error) {
      // If decoding fails, return the original data
      return data;
    }
  }
}

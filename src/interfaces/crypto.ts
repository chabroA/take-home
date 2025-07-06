import { JsonPayload } from '../types/crypto';

export interface EncryptionAlgorithm {
  encrypt(data: string): string;
  decrypt(data: string): string;
}

export interface SigningAlgorithm {
  sign(data: JsonPayload): string;
  verify(data: JsonPayload, signature: string): boolean;
}

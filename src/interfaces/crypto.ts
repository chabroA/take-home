export interface EncryptionAlgorithm {
  encrypt(data: string): string;
  decrypt(data: string): string;
}

export interface SigningAlgorithm {
  sign(data: any): string;
  verify(data: any, signature: string): boolean;
}

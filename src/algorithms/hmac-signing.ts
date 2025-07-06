import { SigningAlgorithm } from '../interfaces/crypto';

export class HmacSigning implements SigningAlgorithm {
  sign(_data: any): string {
    // TODO: Implement signing
    return '';
  }

  verify(_data: any, _signature: string): boolean {
    // TODO: Implement verification
    return false;
  }
}

/**
 * Represents any valid JSON value
 */
type JsonValue =
  | string
  | number
  | boolean
  | null
  | { [key: string]: JsonValue }
  | JsonValue[];

/**
 * Represents a JSON object (key-value pairs)
 */
type JsonObject = { [key: string]: JsonValue };

/**
 * Represents a JSON payload that can be encrypted/decrypted
 * Must be an object (not a primitive or array at the root level)
 */
export type JsonPayload = JsonObject;

/**
 * Represents an encrypted payload where all values are base64 strings
 */
export type EncryptedPayload = { [key: string]: string };

/**
 * Represents a payload with signature for verification
 */
interface SignedPayload {
  signature: string;
  data: JsonPayload;
}

/**
 * Represents the result of a signing operation
 */
export interface SignatureResult {
  signature: string;
}

/**
 * Type guard to check if a value is a valid JsonPayload
 */
export function isJsonPayload(value: unknown): value is JsonPayload {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.prototype.toString.call(value) === '[object Object]'
  );
}

/**
 * Type guard to check if a value is a valid SignedPayload
 */
export function isSignedPayload(value: unknown): value is SignedPayload {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    'signature' in value &&
    'data' in value &&
    typeof (value as Record<string, unknown>).signature === 'string' &&
    isJsonPayload((value as Record<string, unknown>).data)
  );
}

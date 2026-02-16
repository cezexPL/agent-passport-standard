import Ajv2020_ from 'ajv/dist/2020.js';
const Ajv2020 = (Ajv2020_ as any).default ?? Ajv2020_;
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const specDir = resolve(__dirname, '../../spec');

function loadSchema(name: string): object {
  return JSON.parse(readFileSync(resolve(specDir, name), 'utf-8'));
}

export class ValidationError extends Error {
  constructor(message: string, public errors?: unknown[]) {
    super(message);
    this.name = 'ValidationError';
  }
}

function makeValidator(schemaName: string) {
  const schema = loadSchema(schemaName);
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const validate = ajv.compile(schema);
  return (data: unknown): void => {
    if (!validate(data)) {
      const msg = validate.errors?.map((e: any) => `${e.instancePath} ${e.message}`).join('; ') ?? 'validation failed';
      throw new ValidationError(msg, validate.errors ?? undefined);
    }
  };
}

export const validatePassport = makeValidator('agent-passport.schema.json');
export const validateReceipt = makeValidator('work-receipt.schema.json');
export const validateEnvelope = makeValidator('security-envelope.schema.json');
export const validateDNA = makeValidator('dna.schema.json');

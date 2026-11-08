// Local schemas only. URI and date-time are asserted, not annotations.
import Ajv2020 from 'ajv/dist/2020.js';
export function createAjv(options = {}) {
  const ajv = new Ajv2020({ allErrors: true, strict: true, ...options });
  ajv.addFormat('uri', value => {
    try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !/[\s\x00-\x1f]/u.test(value); } catch { return false; }
  });
  ajv.addFormat('date-time', value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value) && !Number.isNaN(Date.parse(value)));
  ajv.addFormat('uri-reference', value => typeof value === 'string' && !/[\s\x00-\x1f]/u.test(value));
  return ajv;
}
export const jsonPointer = value => String(value).replaceAll('~', '~0').replaceAll('/', '~1');
export function schemaErrors(validate, file, code, { prefix = '' } = {}) {
  return (validate.errors ?? []).map(error => ({ severity: 'error', code, message: `${error.message}${error.params?.additionalProperty ? ': ' + error.params.additionalProperty : ''}`, file, field: prefix + error.instancePath + (error.keyword === 'required' ? '/' + jsonPointer(error.params.missingProperty) : '') }));
}
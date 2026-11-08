import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStrictJSON } from '../src/strict-json.mjs';
import { safeRelative, collisionKey } from '../src/paths.mjs';
import { matchesVersion } from '../src/validate.mjs';
const parse = value => parseStrictJSON(Buffer.from(value));

test('strict JSON accepts ordinary nested values', () => {
  assert.deepEqual(parse('{"object":{"x":[true,false,null,-1.5e2,"a\\\"b"]}}'), { object: { x: [true, false, null, -150, 'a"b'] } });
});
for (const input of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":{"y":1,"y":2}}', '{"x":1,}', '{"x":[1,]}', '{}{}', '{"a":NaN}', '{"a":01}', '[]', 'null', '"x"', '{"x":"\\uD800"', '{"x":"\n"}']) {
  test('reject malformed or duplicate JSON ' + JSON.stringify(input), () => assert.throws(() => parse(input)));
}
test('reject BOM and malformed UTF8', () => {
  assert.throws(() => parseStrictJSON(Buffer.from([0xef, 0xbb, 0xbf, 123, 125])));
  assert.throws(() => parseStrictJSON(Buffer.from([123, 34, 120, 34, 58, 34, 0xff, 34, 125])));
});
test('enforce byte and recursion limits', () => {
  assert.throws(() => parseStrictJSON(Buffer.from('{}'), { maxBytes: 1 }));
  assert.throws(() => parseStrictJSON(Buffer.from('{"x":{"x":{}}}'), { maxDepth: 1 }));
});
for (const value of ['/etc/passwd', '../x', 'payload/../x', 'C:/test', 'a\\b', 'a//b', 'a/CON.txt', 'a/nul', 'a/com9.dll', 'a/end.', 'a/end ', 'a/\u0000', 'a/e\u0301', 'a/../', 'a/'.repeat(33) + 'x']) {
  test('reject unsafe path ' + JSON.stringify(value), () => assert.equal(safeRelative(value), false));
}
test('accept normalized safe paths and explicit artifact root', () => {
  assert(safeRelative('payload/shared/资源/manifest.json', { prefix: 'payload' }));
  assert(!safeRelative('licenses/x', { prefix: 'payload' }));
  assert(safeRelative('.', { dot: true }));
  assert.equal(collisionKey('a/straße'), collisionKey('A/STRASSE'));
});
test('version intervals compare components exactly without SemVer guessing', () => {
  const range = { range: { min: '1.2.0', max: '2.0.0', include_min: true, include_max: false } };
  assert(matchesVersion('1.2.0', range));
  assert(matchesVersion('1.10.0', range));
  assert(!matchesVersion('2.0.0', range));
  assert(!matchesVersion('1.2.0.0', range));
  assert(!matchesVersion('1.3.0-rc.1', range));
  assert(matchesVersion('custom-release', { exact: 'custom-release' }));
  assert(!matchesVersion('1.0.0', { exact: '1.0.0.0' }));
});
test('escaped unpaired surrogates rejected without relying on malformed JSON',()=>{
  for (const code of ['D800','DC00']) assert.throws(()=>parse('{"x":"'+String.fromCharCode(92)+'u'+code+'"}'),/Unpaired Unicode surrogate/);
  assert.deepEqual(parse('{"x":"'+String.fromCharCode(92)+'uD83D'+String.fromCharCode(92)+'uDE00"}'),{x:String.fromCodePoint(0x1f600)});
});

'use strict';
const test = require('node:test');
const assert = require('node:assert');
const salvation = require('../../../target/javascript/salvation.min.js');

test('salvation initialization', () => {
    assert.notStrictEqual(salvation.main, undefined);
    salvation.main();
    assert.notStrictEqual(getErrorsForSerializedCSP, undefined);
    assert.notStrictEqual(getErrorsForSerializedCSPList, undefined);
});

test('.getErrorsForSerializedCSP() gives no errors for a valid CSP', () => {
    salvation.main();
    const result = getErrorsForSerializedCSP('default-src \'none\';');
    assert.strictEqual(result.length, 0, 'No errors should be found');
});

test('.getErrorsForSerializedCSP() provides feedback', () => {
    salvation.main();
    const result = getErrorsForSerializedCSP('hello world');
    assert.strictEqual(result, 'Warning at directive 0: Unrecognized directive hello');
});

test('.getErrorsForSerializedCSPList() gives no errors for a valid CSP', () => {
    salvation.main();
    const result = getErrorsForSerializedCSPList('default-src \'none\',plugin-types image/png application/pdf; sandbox,style-src https: \'self\'');
    assert.strictEqual(result, '');
});

test('.getErrorsForSerializedCSPList() provides feedback', () => {
    salvation.main();
    const result = getErrorsForSerializedCSPList('hello,foobar,script-src \'self\'; style-src \'self\'');
    assert.strictEqual(result, 'Warning at directive 0: Unrecognized directive hello\n'
                             + 'Warning at directive 0: Unrecognized directive foobar');
});

const fs = require('fs');
const test = require('tap').test;
const jwa = require('..');

// this key files will be generated as part of `make test`
const testRSAPrivateKey = fs.readFileSync(__dirname + '/rsa-private.pem').toString();
const testRSAPublicKey = fs.readFileSync(__dirname + '/rsa-public.pem').toString();
const testRSAWrongPublicKey = fs.readFileSync(__dirname + '/rsa-wrong-public.pem').toString();

test('jwa: hs256', function (t) {
  const input = 'eugene mirman';
  const secret = 'shhhhhhhhhh';
  const algo = jwa('hs256');
  const sig = algo.sign(input, secret);
  t.ok(algo.verify(input, sig, secret), 'should verify');
  t.notOk(algo.verify(input, 'other sig', secret), 'should verify');
  t.notOk(algo.verify(input, sig, 'incrorect'), 'shoud not verify');
  t.end();
});

test('jwa: hs384', function (t) {
  const input = 'john mullaney';
  const secret = 'shhhhhhhhhh';
  const algo = jwa('hs384');
  const sig = algo.sign(input, secret);
  t.ok(algo.verify(input, sig, secret), 'should verify');
  t.notOk(algo.verify(input, 'other sig', secret), 'should verify');
  t.notOk(algo.verify(input, sig, 'incrorect'), 'shoud not verify');
  t.end();
});

test('jwa: hs512', function (t) {
  const input = 'wyatt cenac';
  const secret = 'shhhhhhhhhh';
  const algo = jwa('hs512');
  const sig = algo.sign(input, secret);
  t.ok(algo.verify(input, sig, secret), 'should verify');
  t.notOk(algo.verify(input, 'other sig', secret), 'should verify');
  t.notOk(algo.verify(input, sig, 'incrorect'), 'shoud not verify');
  t.end();
});

test('jwa: hs512, case-insensitive', function (t) {
  const input = 'mike birbiglia';
  const secret = 'shhhhhhhhhh';
  const algo = jwa('HS512');
  const sig = algo.sign(input, secret);
  t.ok(algo.verify(input, sig, secret), 'should verify');
  t.notOk(algo.verify(input, 'other sig', secret), 'should verify');
  t.notOk(algo.verify(input, sig, 'incrorect'), 'shoud not verify');
  t.end();
});

test('jwa: rs256', function (t) {
  const input = 'h. jon benjamin';
  const algo = jwa('rs256');
  const sig = algo.sign(input, testRSAPrivateKey);
  t.ok(algo.verify(input, sig, testRSAPublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, testRSAWrongPublicKey), 'shoud not verify');
  t.end();
});

test('jwa: rs384', function (t) {
  const input = 'todd barry';
  const algo = jwa('rs384');
  const sig = algo.sign(input, testRSAPrivateKey);
  t.ok(algo.verify(input, sig, testRSAPublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, testRSAWrongPublicKey), 'shoud not verify');
  t.end();
});

test('jwa: rs512', function (t) {
  const input = 'david cross';
  const algo = jwa('rs512');
  const sig = algo.sign(input, testRSAPrivateKey);
  t.ok(algo.verify(input, sig, testRSAPublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, testRSAWrongPublicKey), 'shoud not verify');
  t.end();
});

test('jwa: none', function (t) {
  const input = 'whatever';
  const algo = jwa('none');
  const sig = algo.sign(input);
  t.ok(algo.verify(input, sig), 'should verify');
  t.notOk(algo.verify(input, 'something'), 'shoud not verify');
  t.end();
});

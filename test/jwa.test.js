const base64url = require('base64url');
const spawn = require('child_process').spawn;
const fs = require('fs');
const test = require('tap').test;
const jwa = require('..');

// this key files will be generated as part of `make test`
const rsaPrivateKey = fs.readFileSync(__dirname + '/rsa-private.pem').toString();
const rsaPublicKey = fs.readFileSync(__dirname + '/rsa-public.pem').toString();
const rsaWrongPublicKey = fs.readFileSync(__dirname + '/rsa-wrong-public.pem').toString();
const es256PrivateKey = fs.readFileSync(__dirname + '/ec256-private.pem').toString();
const es256PublicKey = fs.readFileSync(__dirname + '/ec256-public.pem').toString();
const es256WrongPublicKey = fs.readFileSync(__dirname + '/ec256-wrong-public.pem').toString();
const es384PrivateKey = fs.readFileSync(__dirname + '/ec384-private.pem').toString();
const es384PublicKey = fs.readFileSync(__dirname + '/ec384-public.pem').toString();
const es384WrongPublicKey = fs.readFileSync(__dirname + '/ec384-wrong-public.pem').toString();
const es512PrivateKey = fs.readFileSync(__dirname + '/ec512-private.pem').toString();
const es512PublicKey = fs.readFileSync(__dirname + '/ec512-public.pem').toString();
const es512WrongPublicKey = fs.readFileSync(__dirname + '/ec512-wrong-public.pem').toString();


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
  const sig = algo.sign(input, rsaPrivateKey);
  t.ok(algo.verify(input, sig, rsaPublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify');
  t.end();
});

test('jwa: rs384', function (t) {
  const input = 'todd barry';
  const algo = jwa('rs384');
  const sig = algo.sign(input, rsaPrivateKey);
  t.ok(algo.verify(input, sig, rsaPublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify');
  t.end();
});

test('jwa: rs512', function (t) {
  const input = 'david cross';
  const algo = jwa('rs512');
  const sig = algo.sign(input, rsaPrivateKey);
  t.ok(algo.verify(input, sig, rsaPublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify');
  t.end();
});

test('jwa: es256', function (t) {
  const algo = jwa('es256');
  const input = 'strawberry';
  const sig = algo.sign(input, es256PrivateKey);
  t.ok(algo.verify(input, sig, es256PublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, es256WrongPublicKey), 'should not verify');
  t.end();
});

test('jwa: es384', function (t) {
  const algo = jwa('es384');
  const input = 'strawberry';
  const sig = algo.sign(input, es384PrivateKey);
  t.ok(algo.verify(input, sig, es384PublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, es384WrongPublicKey), 'should not verify');
  t.end();
});

test('jwa: es512', function (t) {
  const algo = jwa('es512');
  const input = 'strawberry';
  const sig = algo.sign(input, es512PrivateKey);
  t.ok(algo.verify(input, sig, es512PublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, es512WrongPublicKey), 'should not verify');
  t.end();
});

test('jwa: es512 interop', function (t) {
  const algo = jwa('es512');
  const input = 'strawberry';
  const dgst = spawn('openssl', ['dgst', '-sha512', '-sign', __dirname + '/ec512-private.pem']);
  dgst.stdin.end(input);
  var buffer = Buffer(0);
  dgst.stdout.on('data', function (buf) {
    buffer = Buffer.concat([buffer, buf]);
  });
  dgst.on('exit', function (code) {
    if (code !== 0)
      return t.fail('could not test interop: openssl failure');
    const base64sig = buffer.toString('base64');
    const sig = base64url.fromBase64(base64sig);
    t.ok(algo.verify(input, sig, es512PublicKey), 'should verify');
    t.notOk(algo.verify(input, sig, es512WrongPublicKey), 'should not verify');
    t.end();
  });
});

test('jwa: none', function (t) {
  const input = 'whatever';
  const algo = jwa('none');
  const sig = algo.sign(input);
  t.ok(algo.verify(input, sig), 'should verify');
  t.notOk(algo.verify(input, 'something'), 'shoud not verify');
  t.end();
});

test('jwa: some garbage algorithm', function (t) {
  try {
    jwa('something bogus');
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms');
  }
  t.end();
});

test('jwa: hs512, missing secret', function (t) {
  const algo = jwa('hs512');
  try {
    algo.sign('some stuff');
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/secret/), 'should say something about secrets');
  }
  t.end();
});

test('jwa: hs512, weird input type', function (t) {
  const algo = jwa('hs512');
  const input = {a: ['whatever', 'this', 'is']};
  const secret = 'bones';
  const sig = algo.sign(input, secret);
  t.ok(algo.verify(input, sig, secret), 'should verify');
  t.notOk(algo.verify(input, sig, 'other thing'), 'should not verify');
  t.end();
});

test('jwa: rs512, weird input type', function (t) {
  const algo = jwa('rs512');
  const input = {a: ['whatever', 'this', 'is']};
  const sig = algo.sign(input, rsaPrivateKey);
  t.ok(algo.verify(input, sig, rsaPublicKey), 'should verify');
  t.notOk(algo.verify(input, sig, rsaWrongPublicKey), 'should not verify');
  t.end();
});

test('jwa: rs512, missing signing key', function (t) {
  const algo = jwa('rs512');
  try {
    algo.sign('some stuff');
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/key/), 'should say something about keys');
  }
  t.end();
});

test('jwa: rs512, missing verifying key', function (t) {
  const algo = jwa('rs512');
  const input = {a: ['whatever', 'this', 'is']};
  const sig = algo.sign(input, rsaPrivateKey);
  try {
    algo.verify(input, sig);
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/key/), 'should say something about keys');
  }
  t.end();
});


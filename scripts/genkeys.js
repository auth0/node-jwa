const $ = require('shelljs');

void function genKeys() {
    $.exec('genrsa 2048 > test/rsa-private.pem');
    $.exec('genrsa 2048 > test/rsa-wrong-private.pem');
	$.exec('genrsa -passout pass:test_pass 2048 > test/rsa-passphrase-private.pem');
	$.exec('rsa -in test/rsa-private.pem -pubout > test/rsa-public.pem');
	$.exec('rsa -in test/rsa-wrong-private.pem -pubout > test/rsa-wrong-public.pem');
	$.exec('rsa -in test/rsa-passphrase-private.pem -pubout -passin pass:test_pass > test/rsa-passphrase-public.pem');
	$.exec('ecparam -out test/ec256-private.pem -name prime256v1 -genkey');
	$.exec('ecparam -out test/ec256-wrong-private.pem -name secp256k1 -genkey');
	$.exec('ecparam -out test/ec384-private.pem -name secp384r1 -genkey');
	$.exec('ecparam -out test/ec384-wrong-private.pem -name secp384r1 -genkey');
	$.exec('ecparam -out test/ec512-private.pem -name secp521r1 -genkey');
	$.exec('ecparam -out test/ec512-wrong-private.pem -name secp521r1 -genkey');
	$.exec('ec -in test/ec256-private.pem -pubout > test/ec256-public.pem');
	$.exec('ec -in test/ec256-wrong-private.pem -pubout > test/ec256-wrong-public.pem');
	$.exec('ec -in test/ec384-private.pem -pubout > test/ec384-public.pem');
	$.exec('ec -in test/ec384-wrong-private.pem -pubout > test/ec384-wrong-public.pem');
	$.exec('ec -in test/ec512-private.pem -pubout > test/ec512-public.pem');
    $.exec('ec -in test/ec512-wrong-private.pem -pubout > test/ec512-wrong-public.pem');
    $.touch('test/keys');
}();
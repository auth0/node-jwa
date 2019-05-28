const $ = require(`shelljs`);

void function genKeys() {
	const fixturesPath = `${__dirname}/../test/fixtures`;
    $.exec(`openssl genrsa 2048 > ${fixturesPath}/rsa-private.pem`);
    $.exec(`openssl genrsa 2048 > ${fixturesPath}/rsa-wrong-private.pem`);
	$.exec(`openssl genrsa -passout pass:test_pass 2048 > ${fixturesPath}/rsa-passphrase-private.pem`);
	$.exec(`openssl rsa -in ${fixturesPath}/rsa-private.pem -pubout > ${fixturesPath}/rsa-public.pem`);
	$.exec(`openssl rsa -in ${fixturesPath}/rsa-wrong-private.pem -pubout > ${fixturesPath}/rsa-wrong-public.pem`);
	$.exec(`openssl rsa -in ${fixturesPath}/rsa-passphrase-private.pem -pubout -passin pass:test_pass > ${fixturesPath}/rsa-passphrase-public.pem`);
	$.exec(`openssl ecparam -out ${fixturesPath}/ec256-private.pem -name prime256v1 -genkey`);
	$.exec(`openssl ecparam -out ${fixturesPath}/ec256-wrong-private.pem -name secp256k1 -genkey`);
	$.exec(`openssl ecparam -out ${fixturesPath}/ec384-private.pem -name secp384r1 -genkey`);
	$.exec(`openssl ecparam -out ${fixturesPath}/ec384-wrong-private.pem -name secp384r1 -genkey`);
	$.exec(`openssl ecparam -out ${fixturesPath}/ec512-private.pem -name secp521r1 -genkey`);
	$.exec(`openssl ecparam -out ${fixturesPath}/ec512-wrong-private.pem -name secp521r1 -genkey`);
	$.exec(`openssl ec -in ${fixturesPath}/ec256-private.pem -pubout > ${fixturesPath}/ec256-public.pem`);
	$.exec(`openssl ec -in ${fixturesPath}/ec256-wrong-private.pem -pubout > ${fixturesPath}/ec256-wrong-public.pem`);
	$.exec(`openssl ec -in ${fixturesPath}/ec384-private.pem -pubout > ${fixturesPath}/ec384-public.pem`);
	$.exec(`openssl ec -in ${fixturesPath}/ec384-wrong-private.pem -pubout > ${fixturesPath}/ec384-wrong-public.pem`);
	$.exec(`openssl ec -in ${fixturesPath}/ec512-private.pem -pubout > ${fixturesPath}/ec512-public.pem`);
    $.exec(`openssl ec -in ${fixturesPath}/ec512-wrong-private.pem -pubout > ${fixturesPath}/ec512-wrong-public.pem`);
    $.touch(`${fixturesPath}/keys`);
}();
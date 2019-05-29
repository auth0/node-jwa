const $ = require('shelljs');

void function cleanKeys() {
    $.rm('test/*.pem');
    $.rm('test/keys');
}();

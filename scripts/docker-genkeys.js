const $ = require('shelljs');
const { join } = require('path');
const imageName = 'node-jwa:keys';

function build() {
    console.log(`Building container: ${imageName}`);
    $.exec(`docker build --target genkeys -t ${imageName} .`);
}

function run() {
    console.log(`Generating keys in Docker container: ${imageName}`);
    const fixturesPath = join(__dirname, '..', 'test', 'fixtures');
    const containerMountPath = '/app/test/fixtures';
    console.log(`Mounting volume:\n\t${fixturesPath}\nTo:\n\t${containerMountPath}`);
    $.exec(`docker run --rm -v ${fixturesPath}:${containerMountPath} ${imageName}`);
}

void function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        build();
        run();
        return;
    }

    if ('build' in args)
        build();
    
    if ('run' in args)
        run();
}();



/**
 * @type {jest.ProjectConfig}
 */
module.exports = {
    transform: {
        '^.+\\.tsx?$': 'ts-jest'
    },
    roots: [
        '<rootDir>/test/unit'
    ],
    testRegex: '(.*|(\\.|/)(test|spec))\\.ts$',
    moduleFileExtensions: [
        'ts',
        'tsx',
        'js',
        'jsx',
        'json',
        'node'
    ],
};

const defaultConfig = require('./jest.config');

/**
 * @type {jest.ProjectConfig}
 */

 defaultConfig.roots.push('<rootDir>/test/integration');

 module.exports = defaultConfig;
 
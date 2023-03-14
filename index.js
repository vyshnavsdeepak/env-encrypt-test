const fs = require('fs');
const dotenv = require('dotenv');
const { encryptEnvFile, writeEncrypted, writeDecrypted, getDecryptedEnvVars } = require('./encryptedConfig');

const readEnvFile = () => {
  const envFile = fs.readFileSync('.env');
  const envVars = dotenv.parse(envFile);
  return envVars;
}

const readPublicKey = (folder) => {
  const pb = fs.readFileSync(`${folder}/publickey.pem`);
  return pb;
}

(async () => {
  const config = readEnvFile();
  // const text = "Hello World";
  const publicKey1 = readPublicKey('./key1');

  const encrypted = encryptEnvFile(config, publicKey1,
    fs.readFileSync('./key1/privatekey.pem'), [readPublicKey('./key2')]);
  writeEncrypted(encrypted);

  // writeDecrypted(getDecryptedEnvVars());
})();
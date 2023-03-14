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
  const config = readEnvFile(); // Read .env file
  const publicKey1 = readPublicKey('./key1'); // file encryption key

  const private1 = fs.readFileSync('./key1/privatekey.pem'); // file decryption key

  const publicKey2 = readPublicKey('./key2'); // user encryption key

  // const encrypted = encryptEnvFile(config, publicKey1,
  //   private1, [publicKey2]);
  // writeEncrypted(encrypted);

  // Uncommnt the above to encrypt the .env file, commnent the below while doing that and vice versa

  // Decrypt with key2, key2 is user key
  writeDecrypted(getDecryptedEnvVars(
    fs.readFileSync('./key2/privatekey.pem'),
  ));
})();
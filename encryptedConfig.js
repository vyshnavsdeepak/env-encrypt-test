const fs = require('fs');
const dotenv = require('dotenv');
const crypto = require('crypto');

const encryptedStringBase = 'base64';

const encryptText = (text, publicKey) => {
  const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(text)).toString(encryptedStringBase);
  return encrypted;
};

const decryptText = (encryptedText, privateKey) => {
  const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedText, encryptedStringBase)).toString('utf8');
  return decrypted;
};

const encryptEnvFile = (envVars, publicKey, privateKey) => {
  console.log({
    envVars
  })
  const encryptedVars = {};
  console.log({
    envVars
  })
  Object.keys(envVars).forEach((key) => {
    encryptedVars[key] = encryptText(envVars[key], publicKey);
  });


  return {
    privateKey: privateKey.toString('base64'),
    encryptedVars,
  };
}

const writeEncrypted = (envVars) => {
  console.log(envVars);
  fs.writeFileSync(".env.enc", JSON.stringify(envVars), 'utf8');
}

const readEncrypted = () => {
  const envFile = fs.readFileSync('.env.enc');
  const envVars = JSON.parse(envFile);
  return {
    privateKey: envVars.privateKey,
    encryptedVars: envVars.encryptedVars,
  };
}

const getDecryptedEnvVars = () => {
  const encrypted = readEncrypted();
  const privateKey = Buffer.from(encrypted.privateKey, 'base64');
  const encryptedVars = encrypted.encryptedVars;
  const decryptedVars = {};
  Object.keys(encryptedVars).forEach((key) => {
    decryptedVars[key] = decryptText(encryptedVars[key], privateKey);
  });
  return decryptedVars;
}

const writeDecrypted = (envVars) => {
  fs.writeFileSync(".env-d", JSON.stringify(envVars), 'utf8');
}



module.exports = {
  encryptEnvFile,
  writeEncrypted,
  writeDecrypted,
  getDecryptedEnvVars,
}
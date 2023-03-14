const fs = require('fs');
const dotenv = require('dotenv');
const crypto = require('crypto');

const encryptedStringBase = 'base64';

const encryptText = (text, publicKey) => {
  try {
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(text)).toString(encryptedStringBase);
    return encrypted;

  } catch (error) {
    console.log({
      errortext: text,
      error
    })
    throw error;
  }
};

const decryptText = (encryptedText, privateKey) => {
  const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedText, encryptedStringBase)).toString('utf8');
  return decrypted;
};

const encryptEnvFile = (envVars, publicKey, privateKey, userPublicKeys) => {
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

  // Encrypt private key with user public keys
  const symKey = crypto.randomBytes(32);

  const symKeysEncrypted = [];
  const encryptedPrivateKey = crypto.privateEncrypt(privateKey, symKey).toString(encryptedStringBase);
  Object.keys(userPublicKeys).forEach((key) => {
    symKeysEncrypted.push(encryptText(symKey.toString('base64'), userPublicKeys[key]));
  });

  return {
    encryptedPrivateKey,
    encryptedVars,
    symKeysEncrypted
  };
}

const writeEncrypted = (envVars) => {
  console.log(envVars);
  fs.writeFileSync(".env.enc", JSON.stringify(envVars, null, 2), 'utf8');
}

const readEncrypted = () => {
  const envFile = fs.readFileSync('.env.enc');
  const envVars = JSON.parse(envFile);
  return {
    encryptedPrivateKeys: envVars.encryptedPrivateKeys,
    encryptedVars: envVars.encryptedVars,
  };
}

const getDecryptedEnvVars = (userKey) => {
  const encrypted = readEncrypted();
  const ecryptedPrivateKeys = encrypted.encryptedPrivateKeys;

  // Decrypt private key with user private key
  let privateKey = null;
  ecryptedPrivateKeys.forEach((key) => {
    try {
      privateKey = decryptText(key, userKey);
    } catch (e) {
      console.log(e);
    }
  });

  if (!privateKey) {
    throw new Error('Could not decrypt private key');
  }

  // const privateKey = Buffer.from(encrypted.privateKey, 'base64');
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
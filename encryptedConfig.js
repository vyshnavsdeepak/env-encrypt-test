const fs = require('fs');
const dotenv = require('dotenv');
const crypto = require('crypto');

const encryptedStringBase = 'base64';

const s = () => {
  // Generate a random symmetric encryption key
  const key = crypto.randomBytes(32);
  // Encrypt a message using the symmetric key
  const iv = crypto.randomBytes(16); // Generate a random initialization vector
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encryptedMessage = cipher.update(message, 'utf8', 'hex');
  encryptedMessage += cipher.final('hex');

  console.log(`Encrypted message: ${encryptedMessage}`);

  // Decrypt the message using the symmetric key
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8');
  decryptedMessage += decipher.final('utf8');

  console.log(`Decrypted message: ${decryptedMessage}`);
}

const getCipher = (key, iv) => {
  key =  key ?? crypto.randomBytes(32);
  // Encrypt a message using the symmetric key
  iv = iv ?? crypto.randomBytes(16); // Generate a random initialization vector
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return {
    key,
    iv,
    cipher,
  };
}

const encryptWithCipher = (cipher, message) => {
  let encryptedMessage = cipher.update(message, 'utf8', 'hex');
  encryptedMessage += cipher.final('hex');
  return encryptedMessage;
}

const decryptWithCipher = ({ key, iv }, encryptedMessage) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  console.log({
    encryptedMessage
  })
  let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8');
  decryptedMessage += decipher.final('utf8');
  return decryptedMessage;
}

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
  const encryptedVars = {};
  console.log({
    envVars
  })
  Object.keys(envVars).forEach((key) => {
    encryptedVars[key] = encryptText(envVars[key], publicKey);
  });

  // Encrypt private key with user public keys
  const cipher = getCipher();
  const symKey = cipher.cipher;


  console.log({
    cipher: cipher
  });
  const encryptedPrivateKey = encryptWithCipher(symKey, privateKey);

  const cipherCreateEncrypted = [];

  const cipherCreate = JSON.stringify({
    key: cipher.key.toString('base64'),
    iv: cipher.iv.toString('base64'),
  })

  Object.keys(userPublicKeys).forEach((key) => {
    cipherCreateEncrypted.push(encryptText(cipherCreate, userPublicKeys[key]));
  });

  return {
    encryptedPrivateKey,
    encryptedVars,
    cipherCreateEncrypted
  };
}

const writeEncrypted = (envVars) => {
  fs.writeFileSync(".env.enc", JSON.stringify(envVars, null, 2), 'utf8');
}

const readEncrypted = () => {
  const envFile = fs.readFileSync('.env.enc');
  const envVars = JSON.parse(envFile);
  return {
    cipherCreateEncrypted: envVars.cipherCreateEncrypted,
    encryptedPrivateKey: envVars.encryptedPrivateKey,
    encryptedVars: envVars.encryptedVars,
  };
}

const getDecryptedEnvVars = (userKey) => {
  const encrypted = readEncrypted();
  const cipherCreateEncrypted = encrypted.cipherCreateEncrypted;
  const encryptedPrivateKey = encrypted.encryptedPrivateKey;

  console.log({
    encryptedPrivateKey,
  });

  // Decrypt private key with user private key
  let cipherCreate = null;
  cipherCreateEncrypted.forEach((key) => {
    try {
      cipherCreate = JSON.parse(decryptText(key, userKey));
    } catch (e) {
      console.log(e);
    }
  })

  console.log("SymKey", cipherCreate);

  if (!cipherCreate) {
    throw new Error('Could not decrypt cypher key');
  }

  const privateKey = decryptWithCipher({
    key: Buffer.from(cipherCreate.key, 'base64'),
    iv: Buffer.from(cipherCreate.iv, 'base64'),
  }, encryptedPrivateKey);
  // const privateKey = Buffer.from(encrypted.privateKey, 'base64');
  const encryptedVars = encrypted.encryptedVars;
  const decryptedVars = {};
  Object.keys(encryptedVars).forEach((key) => {
    decryptedVars[key] = decryptText(encryptedVars[key], privateKey);
  });
  return decryptedVars;
}

const writeDecrypted = (envVars) => {
  fs.writeFileSync(".env-d", JSON.stringify(envVars, null, 2), 'utf8');
}



module.exports = {
  encryptEnvFile,
  writeEncrypted,
  writeDecrypted,
  getDecryptedEnvVars,
}
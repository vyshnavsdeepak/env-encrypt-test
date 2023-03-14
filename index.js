const fs = require('fs');
const dotenv = require('dotenv');

const readEnvFile =  () => {
  const envFile = fs.readFileSync('.env');
  const envVars = dotenv.parse(envFile);
  return envVars;
}


(async () => {
  const config = readEnvFile();

  console.log(config);

})();
const fs = require('fs');

const mainJsPath = __dirname + '/../public/main.js';
const mainJsContent = fs.readFileSync(mainJsPath).toString();

fs.writeFileSync(mainJsPath, '// Licenses available at https://cspvalidator.org/licenses.json\n' + mainJsContent);

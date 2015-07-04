```sh
npm install
```
```sh
npm run build && node --harmony_generators dist/index.js
```


To generate test self-signed certificate that expires in XXX days:
```sh
openssl req -x509 -sha256 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX
```

To remove the passphrase:
```sh
openssl rsa -in key.pem -out newkey.pem && mv newkey.pem key.pem
```

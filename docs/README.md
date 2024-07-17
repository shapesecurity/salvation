# Installation
```sh
npm install
```

## Development Build
```sh
npm run dev
```

## Production Build
```sh
npm run build
```

# Note on salvation.min.js

This comes from [Salvation](https://github.com/shapesecurity/salvation). It is automatically generated at compile time using [TeaVM](https://teavm.org/docs/intro/getting-started.html). And needs to be manually copied to `docs/static/`.

To update the version of Salvation used in this demo website, follow the instructions provided in the README located at the root of this repo. Copy the generated file to `docs/static/`, then rename it to `salvation.min.js`.

module.exports = {
  presets: [
    '@babel/preset-env',
    ['@babel/preset-react', {
      runtime: 'automatic',
      development: process.env.NODE_ENV === 'development',
    }],
  ],
  targets: {
    browsers: '> 0.5%, last 10 versions',
  },
  plugins: [
    '@babel/plugin-transform-runtime',
    [
      '@babel/plugin-transform-react-jsx',
      {
        runtime: 'automatic',
        importSource: 'preact',
      },
    ],
  ],
};

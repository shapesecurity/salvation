'use strict';
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const path = require('path');
const ESLintPlugin = require('eslint-webpack-plugin');
const LicensePlugin = require('webpack-license-plugin');
const TerserPlugin = require('terser-webpack-plugin');

module.exports = {
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  entry: './src/index.js',
  optimization: {
    usedExports: false,
    minimizer: [
      new TerserPlugin({
        extractComments: false,
      }),
    ],
  },
  output: {
    path: path.resolve(__dirname, 'public'),
    filename: 'main.js',
  },
  target: 'web',
  devtool: 'cheap-module-source-map',
  devServer: {
    port: '9500',
    static: ['./dist', './static'],
    open: true,
    hot: true,
    liveReload: true,
  },
  resolve: {
    extensions: ['.js', '.jsx', '.json'],
    alias: {
      'react': 'preact/compat',
      'react-dom/test-utils': 'preact/test-utils',
      'react-dom': 'preact/compat', // Must be below test-utils
      'react/jsx-runtime': 'preact/jsx-runtime',
    },
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: 'babel-loader',
      },
      {
        test: /\.css$/i,
        use: ['style-loader', 'css-loader'],
      },
    ],
  },
  plugins: [
    new HtmlWebpackPlugin({ template: './static/index.html' }),
    new CopyWebpackPlugin({
      patterns: [
        { from: 'static/salvation.min.js', to: 'salvation.min.js' },
        { from: 'static/favicon', to: 'favicon' },
      ],
    }),
    new ESLintPlugin({
      overrideConfigFile: './.eslintrc.js',
      extensions: ['js', 'jsx'],
      failOnError: false,
    }),
    new LicensePlugin({
      outputFilename: 'licenses.json',
      replenishDefaultLicenseTexts: true,
      includePackages: async () => [
        'node_modules/bootstrap',
        'node_modules/bootstrap-icons',
      ],
    }),
  ],
};

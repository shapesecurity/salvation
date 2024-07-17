'use strict';
const { defineConfig } = require('eslint-define-config');

module.exports = defineConfig({
  extends: [
    'eslint:recommended',
    'plugin:react/recommended',
    'plugin:jsx-a11y/recommended',
  ],
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    ecmaFeatures: {
      jsx: true,
    },
  },
  reportUnusedDisableDirectives: true,
  root: true,
  rules: {
    'array-element-newline': ['error', 'consistent'],
    'arrow-body-style': 'error',
    'array-bracket-spacing': ['error', 'never'],
    'arrow-parens': ['error', 'as-needed'],
    'brace-style': ['error', '1tbs'],
    'camelcase': 'error',
    'comma-dangle': ['error', 'always-multiline'],
    'comma-spacing': ['error', { before: false, after: true }],
    'comma-style': ['error', 'last'],
    'computed-property-spacing': ['error', 'never'],
    'consistent-return': 'error',
    'curly': ['error', 'multi-line'],
    'dot-notation': 'error',
    'eol-last': 'error',
    'eqeqeq': ['error', 'smart'],
    'func-call-spacing': 'error',
    'guard-for-in': 'error',
    'indent': [
      'error',
      2,
      {
        SwitchCase: 1,
        VariableDeclarator: {
          var: 2,
          let: 2,
          const: 3,
        },
      },
    ],
    'key-spacing': [
      'error',
      {
        beforeColon: false,
        afterColon: true,
      },
    ],
    'keyword-spacing': 'error',
    'max-statements-per-line': 'error',
    'no-alert': 'error',
    'no-caller': 'error',
    'no-else-return': 'error',
    'no-empty': [
      'error',
      {
        allowEmptyCatch: true,
      },
    ],
    'no-eval': 'error',
    'no-extend-native': 'error',
    'no-extra-bind': 'error',
    'no-floating-decimal': 'error',
    'no-implied-eval': 'error',
    'no-inner-declarations': ['error', 'both'],
    'no-lonely-if': 'error',
    'no-loop-func': 'error',
    'no-multi-spaces': 'error',
    'no-multiple-empty-lines': [
      'error',
      {
        max: 2,
      },
    ],
    'no-param-reassign': 'warn',

    'no-return-assign': 'error',
    'no-self-compare': 'error',
    'no-sequences': 'error',
    'no-shadow': ['error', { builtinGlobals: true }],
    'no-trailing-spaces': 'error',
    'no-undefined': 'error',
    'no-unused-expressions': 'error',
    'no-unused-vars': ['error', { vars: 'all', args: 'after-used' }],
    'no-use-before-define': ['error', 'nofunc'],
    'no-useless-call': 'error',
    'no-var': 'error',
    'no-with': 'error',
    'object-curly-spacing': ['error', 'always'],
    'object-property-newline': [
      'error',
      {
        allowAllPropertiesOnSameLine: true,
      },
    ],
    'object-shorthand': ['error', 'always'],
    'prefer-arrow-callback': ['error'],
    'quotes': ['error', 'single', { avoidEscape: true }],
    'semi': ['error', 'always'],
    'semi-spacing': [
      'error',
      {
        before: false,
        after: true,
      },
    ],
    'space-before-blocks': 'error',
    'space-before-function-paren': ['error', { anonymous: 'always', named: 'never' }],
    'space-in-parens': 'error',
    'space-infix-ops': 'error',
    'space-unary-ops': 'error',
    'spaced-comment': [
      'warn',
      'always',
      {
        block: {
          markers: ['!'],
          exceptions: ['*'],
        },
        line: {
          markers: ['/'],
        },
      },
    ],
    'wrap-iife': ['error', 'inside'],
    'yoda': ['error', 'never'],
  },
  settings: {
    react: {
      version: 'detect',
    },
  },
  overrides: [
    {
      files: ['*.js', '*.jsx'],
    },
    {
      files: [
        'webpack.config.js',
        '.eslintrc.js',
      ],
      env: {
        node: true,
      },
    },
  ],
});

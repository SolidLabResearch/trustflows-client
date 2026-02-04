import opinionated from 'opinionated-eslint-config';

export default opinionated().append(
  {
    // Don't want to lint test assets
    ignores: [
      'test/assets/*',
      'componentsjs-error-state.json',
      'temp-client/logs/**',
      'temp-client/vendor/**',
    ],
  },
  {
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: [ './tsconfig.eslint.json' ],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
);

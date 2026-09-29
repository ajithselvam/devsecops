// Flat ESLint config. Deliberately minimal: correctness rules only, no style
// opinions, so linting stays useful on this codebase without demanding a
// large formatting refactor.
const tseslint = require('typescript-eslint');

module.exports = tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**', 'scripts/**', '*.mjs', '*.mts']
  },
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: __dirname
      }
    },
    rules: {
      // The DAL and route handlers are deliberately dynamic at the edges.
      '@typescript-eslint/no-explicit-any': 'off',
      // Fastify handlers must keep their full (request, reply) signature even
      // when one side is unused, so args are not reported. Unused locals are
      // still worth surfacing, but as warnings.
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { args: 'none', varsIgnorePattern: '^_', caughtErrors: 'none' }
      ],
      '@typescript-eslint/no-empty-object-type': 'off'
    }
  }
);

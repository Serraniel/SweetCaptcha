// esbuild bundles CSS imported for its side effects. TypeScript 7 requires a
// declaration for such imports.
declare module '*.css';

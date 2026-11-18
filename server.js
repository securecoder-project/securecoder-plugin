// OpenCode 2.x entry point. OpenCode loads the server part of a plugin
// directory from its root `server.js`, whatever package.json `exports` says,
// so this re-exports the adapter in opencode/.
export { default } from './opencode/index.js';

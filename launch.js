// Starts the Electron app. ELECTRON_RUN_AS_NODE is cleared because terminals inside
// VS Code (itself an Electron app) can inherit it, which would make Electron act as plain Node.
// --detach lets the launcher exit immediately (used by the .bat so no console window lingers).
const { spawn } = require('child_process');
const electron = require('electron');

const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;

const args = process.argv.slice(2);
const detach = args.includes('--detach');
const files = args.filter((a) => a !== '--detach');

const child = spawn(electron, [__dirname, ...files], {
  env,
  detached: detach,
  stdio: detach ? 'ignore' : 'inherit',
});
if (detach) child.unref();
else child.on('close', (code) => process.exit(code ?? 0));

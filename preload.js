const { contextBridge, ipcRenderer, webUtils } = require('electron');

const call = (ch) => (arg) => ipcRenderer.invoke(ch, arg);
const on = (ch) => (cb) => ipcRenderer.on(ch, (_e, data) => cb(data));

contextBridge.exposeInMainWorld('api', {
  pathForFile: (file) => webUtils.getPathForFile(file),

  // jobs
  enqueue: (id, file) => ipcRenderer.invoke('enqueue', { id, file }),
  cancelJob: call('cancel-job'),
  pickFiles: call('pick-files'),
  openFolder: call('open-folder'),

  // settings, history, bookmarks
  getSettings: call('get-settings'),
  setSettings: call('set-settings'),
  chooseOutput: call('choose-output'),
  getHistory: call('get-history'),
  removeHistory: (outDir, deleteFiles) => ipcRenderer.invoke('remove-history', { outDir, deleteFiles }),
  getBookmarks: call('get-bookmarks'),
  setBookmarks: (outDir, list) => ipcRenderer.invoke('set-bookmarks', { outDir, list }),

  // browsing output
  listFiles: call('list-files'),
  readFile: (outDir, rel) => ipcRenderer.invoke('read-file', { outDir, rel }),
  fullPath: (outDir, rel) => ipcRenderer.invoke('full-path', { outDir, rel }),
  search: call('search'),
  cancelSearch: call('cancel-search'),
  openPath: call('open-path'),
  openOutputRoot: call('open-output-root'),
  showFile: (outDir, rel) => ipcRenderer.invoke('show-file', { outDir, rel }),
  copyText: call('copy-text'),
  exportZip: (outDir, sub) => ipcRenderer.invoke('export-zip', { outDir, sub }),
  saveFileAs: (outDir, rel) => ipcRenderer.invoke('save-file-as', { outDir, rel }),
  rebuild: call('rebuild'),
  onRebuildLog: on('rebuild-log'),

  // tools
  toolStatus: call('tool-status'),
  removeTool: call('remove-tool'),
  openToolsDir: call('open-tools-dir'),
  appAction: call('app-action'),

  // AI assistant
  aiConfig: call('ai-config'),
  aiSetKey: call('ai-set-key'),
  aiSend: (outDir, opts) => ipcRenderer.invoke('ai-send', { outDir, ...opts }),
  aiStop: call('ai-stop'),
  aiReset: call('ai-reset'),
  aiLogin: call('ai-login'),
  aiLoginCancel: call('ai-login-cancel'),
  aiLogout: call('ai-logout'),
  onAiEvent: on('ai-event'),
  onAiLoginLog: on('ai-login-log'),

  // events from the main process
  onAddFiles: on('add-files'),
  onJobEvent: on('job-event'),
  onFocusJob: on('focus-job'),
  onSearchProgress: on('search-progress'),
  onTheme: on('theme'),
});

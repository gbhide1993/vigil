const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('vlaw', {
  sendAction: (type, alertId, agentId) =>
    ipcRenderer.invoke('send-action', { type, alertId, agentId }),
  onAlertState: (callback) => {
    ipcRenderer.on('alert-state', (_event, data) => callback(data))
  },
  hideFlyout: () => ipcRenderer.send('hide-flyout'),
})

const os = require('os')
const platform = os.platform()

const impl = platform === 'darwin'
  ? require('./full-tunnel-darwin')
  : require('./full-tunnel-linux')

module.exports = {
  enableServerForwarding: impl.enableServerForwarding,
  disableServerForwarding: impl.disableServerForwarding,
  enableClientFullTunnel: impl.enableClientFullTunnel,
  addHostExemption: impl.addHostExemption,
  disableClientFullTunnel: impl.disableClientFullTunnel
}

// The start page: follows its own session, and opens a wallet on this device when asked. It runs after
// shared.js in the same inline module, which supplies config, followSession, postJson and setStatus.

followSession();

const sameDeviceButton = document.getElementById('same-device');
if (sameDeviceButton !== null && config.sameDeviceUrl) {
  // The request bound to this browser is minted only when asked for, and the wallet is opened only once
  // the binding exists, so a failure leaves the wallet unopened rather than opened unbound.
  sameDeviceButton.addEventListener('click', async () => {
    sameDeviceButton.disabled = true;
    try {
      const { walletUrl } = await postJson(config.sameDeviceUrl, {});
      window.location.assign(walletUrl);
    } catch (error) {
      setStatus(`Could not open a wallet on this device: ${error.message}`, 'fail');
      sameDeviceButton.disabled = false;
    }
  });
}

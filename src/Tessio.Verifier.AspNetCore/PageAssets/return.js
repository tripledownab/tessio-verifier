// The return page a wallet's redirect lands on: redeems the response code, then follows the session. It
// runs after shared.js in the same inline module, which supplies config, followSession, postJson and
// setStatus.

const responseCode = new URLSearchParams(window.location.hash.slice(1)).get('response_code');
// The code is good for one redemption. Taking it off the address bar keeps it out of history.
history.replaceState(null, '', window.location.pathname + window.location.search);

if (responseCode === null || !config.redeemUrl) {
  // No code, or a deployment without the same-device flow: there is nothing to redeem, so the page shows
  // the session as it stands.
  followSession();
} else {
  try {
    const { result } = await postJson(config.redeemUrl, { responseCode });
    if (result === 'session_mismatch') {
      setStatus('This request was started in another browser, so the presentation was rejected. Start again in this browser.', 'fail');
    } else if (result === 'not_held') {
      // Nothing was waiting: a cross-device session, whose stream shows its outcome, or a presentation
      // whose window passed, which leaves the session open for the wallet to answer again.
      followSession('No presentation is waiting to be confirmed. Open your wallet again to retry.');
    } else {
      followSession();
    }
  } catch (error) {
    setStatus(`Could not confirm the presentation: ${error.message}`, 'fail');
  }
}

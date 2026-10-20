namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The markup, styles and scripts of the hosted pages, as fixed text. <see cref="HostedPages"/> fills in
/// the placeholders; nothing here is built from a value.
/// </summary>
/// <remarks>
/// Each page runs one module script: <see cref="SharedScript"/> followed by the page's own. A module runs
/// in strict mode, after the document is parsed, with its names kept out of the global scope. It reads
/// its values from the <c>page-config</c> JSON block, and everything that came from a presentation
/// reaches the page through <c>textContent</c>, never <c>innerHTML</c>: an issuer identifier is the
/// presenter's own string, and a failing result carries it.
/// </remarks>
internal static class HostedPageAssets
{
    public const string PageTemplate = """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Tessio.Verifier verification</title>
          <style>
            :root { color-scheme: light dark; }
            body { font: 15px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
            h1 { font-size: 1.4rem; margin-bottom: .25rem; }
            .badge { display: inline-block; padding: .1rem .5rem; border-radius: 1rem; background: #5b6cff; color: #fff; font-size: .75rem; font-weight: 600; }
            .status { font-size: 1.1rem; font-weight: 600; padding: .75rem 1rem; border-radius: .5rem; background: #8883; margin: 1rem 0; }
            .status.ok { background: #2e7d3222; color: #2e7d32; }
            .status.fail { background: #c6282822; color: #c62828; }
            code { word-break: break-all; font-size: .8rem; }
            .req { background: #8881; padding: .75rem; border-radius: .5rem; }
            .qr { margin: .75rem 0; }
            .qr svg { width: 240px; height: 240px; display: block; background: #fff; padding: 8px; border-radius: .5rem; }
            table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
            td { border-bottom: 1px solid #8883; padding: .35rem .5rem; }
            td:first-child { font-weight: 600; width: 40%; }
            .issuer { color: #888; font-size: .8rem; }
          </style>
        </head>
        <body>
          __BODY__
          <script id="page-config" type="application/json">__CONFIG__</script>
          <script type="module">__SCRIPT__</script>
        </body>
        </html>
        """;

    public const string StartBody = """
        <h1>Tessio.Verifier <span class="badge">__MODE__ mode</span></h1>
        <p>Session <code>__SESSION_ID__</code></p>
        <div id="status" class="status pending">Starting…</div>
        <div id="claims"></div>
        __SAME_DEVICE_BUTTON__
        <details __DETAILS_OPEN__>
          <summary>Authorization request (scan with a wallet)</summary>
          <div class="qr">__QR_SVG__</div>
          <p class="req"><code>__AUTH_URI__</code></p>
          <p><a href="__STATUS_URL__">Raw status JSON</a></p>
        </details>
        """;

    public const string SameDeviceButton = """
        <p><button id="same-device" type="button">Open a wallet on this device</button></p>
        """;

    public const string ReturnBody = """
        <h1>Tessio.Verifier</h1>
        <p>Session <code>__SESSION_ID__</code></p>
        <div id="status" class="status pending">Checking…</div>
        <div id="claims"></div>
        """;

    public const string SharedScript = """

        const config = JSON.parse(document.getElementById('page-config').textContent);
        const statusElement = document.getElementById('status');
        const claimsElement = document.getElementById('claims');

        function setStatus(text, kind) {
          statusElement.textContent = text;
          statusElement.className = `status ${kind}`;
        }

        function showResult(result) {
          claimsElement.replaceChildren();
          if (!result) {
            return;
          }

          const table = document.createElement('table');
          for (const [name, value] of Object.entries(result.disclosedClaims ?? {})) {
            const row = table.insertRow();
            row.insertCell().textContent = name;
            row.insertCell().textContent = String(value);
          }

          const issuer = document.createElement('p');
          issuer.className = 'issuer';
          issuer.textContent =
            `Issuer: ${result.issuer.identifier} · trusted: ${result.issuer.trusted} · key: ${result.issuer.keyResolutionMethod}`;
          claimsElement.append(table, issuer);
        }

        function followSession(pendingText = 'Waiting for wallet…') {
          const events = new EventSource(config.streamUrl);
          events.addEventListener('pending', () => setStatus(pendingText, 'pending'));
          events.addEventListener('completed', (event) => {
            const { result } = JSON.parse(event.data);
            const verified = result?.isValid === true;
            setStatus(verified ? 'Verified ✓' : 'Verification failed ✗', verified ? 'ok' : 'fail');
            showResult(result);
            events.close();
          });
          events.addEventListener('attempt_failed', () => {
            setStatus('The wallet\'s answer was refused. Waiting for another…', 'fail');
          });
          events.addEventListener('expired', () => {
            setStatus('Session expired', 'fail');
            events.close();
          });
          // EventSource reconnects by itself after a dropped connection. Closed means it has given up, which
          // it does when the server refuses the stream, for example a session that no longer exists.
          events.addEventListener('error', () => {
            if (events.readyState === EventSource.CLOSED) {
              setStatus('Lost the connection to the verifier. Reload the page to check again.', 'fail');
            }
          });
        }

        async function postJson(url, body) {
          const response = await fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          if (!response.ok) {
            throw new Error(`the server answered ${response.status}`);
          }

          return response.json();
        }

        """;

    public const string StartScript = """
        followSession();

        const sameDeviceButton = document.getElementById('same-device');
        if (sameDeviceButton !== null && config.sameDeviceUrl) {
          // The request bound to this browser is minted only when asked for, and the wallet is opened only
          // once the binding exists, so a failure leaves the wallet unopened rather than opened unbound.
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

        """;

    public const string ReturnScript = """
        const responseCode = new URLSearchParams(window.location.hash.slice(1)).get('response_code');
        // The code is good for one redemption. Taking it off the address bar keeps it out of history.
        history.replaceState(null, '', window.location.pathname + window.location.search);

        if (responseCode === null || !config.redeemUrl) {
          // No code, or a deployment without the same-device flow: there is nothing to redeem, so the page
          // shows the session as it stands.
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

        """;
}

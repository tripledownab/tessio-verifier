// What every hosted page shares: its configuration block, the status line, the result table and the
// session stream. HostedPageAssets puts this before the page's own script in one inline module, so the names
// below are the page script's to use. Everything that came from a presentation reaches the page through
// textContent, never as markup: an issuer identifier is the presenter's own string, and a failing result
// carries it.

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
  // EventSource reconnects by itself after a dropped connection. Closed means it has given up, which it
  // does when the server refuses the stream, for example a session that no longer exists.
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

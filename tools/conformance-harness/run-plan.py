#!/usr/bin/env python3
"""Run an OIDF verifier test plan against the harness without a browser.

The suite plays the wallet and drives everything itself once it has the authorization request, so a
whole plan can run from the command line. Two uses:

  regression   run the plan, compare every module against what it is supposed to do, exit non-zero on
               any mismatch. Use this after changing OpenID4VP behaviour.
  evidence     the same, plus screenshot each evidence page and upload it to the module, so the plan
               completes with the artifacts certification needs.

See README.md for the one-time setup. This script does not create key material and does not publish a
plan: publishing makes a run publicly visible and belongs with the decision to certify.
"""

import argparse
import base64
import json
import re
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

# What each module is supposed to do. Unknown modules are a hard error rather than a guess: the suite
# adds modules over time, and quietly assuming a new one is positive would report a pass we never made.
ACCEPT, REJECT, SUITE_DECIDES = "accept", "reject", "suite"
EXPECTED = {
    "oid4vp-1final-verifier-happy-flow": ACCEPT,
    "oid4vp-1final-verifier-minimal-cnf-jwk": ACCEPT,
    "oid4vp-1final-verifier-request-uri-fetched-twice": ACCEPT,
    # Only applies to a verifier that advertises request_uri_method=post. We do not, so the suite skips
    # it and the harness is never called.
    "oid4vp-1final-verifier-request-uri-method-post": SUITE_DECIDES,
    # mdoc only: the device signature covers a session transcript the suite deliberately gets wrong.
    "oid4vp-1final-verifier-invalid-session-transcript": REJECT,
    "oid4vp-1final-verifier-invalid-kb-jwt-signature": REJECT,
    "oid4vp-1final-verifier-invalid-credential-signature": REJECT,
    "oid4vp-1final-verifier-invalid-sd-hash": REJECT,
    "oid4vp-1final-verifier-invalid-kb-jwt-nonce": REJECT,
    "oid4vp-1final-verifier-invalid-kb-jwt-aud": REJECT,
    "oid4vp-1final-verifier-kb-jwt-iat-in-past": REJECT,
    "oid4vp-1final-verifier-kb-jwt-iat-in-future": REJECT,
}

MODULE_VARIANT = {"client_id_prefix": "x509_hash", "request_method": "request_uri_signed", "vp_profile": "haip"}

# Both ends are deliberately self-signed. The suite generates its own certificate and the harness signs
# its TLS with the throwaway CA it mints, which the README explains. Verification here would only fail
# on that known-good chain.
TLS = ssl._create_unverified_context()


class _KeepRedirect(urllib.request.HTTPRedirectHandler):
    """Report a redirect instead of following it. The suite finishes its work when it receives the
    authorization request; the redirect only says where a browser would go next, and it names the host
    the suite reaches us on, which by design does not resolve outside the container."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_KeepRedirect, urllib.request.HTTPSHandler(context=TLS))


def http(url, method="GET", body=None, content_type=None, timeout=90):
    """The status and body, for any status. Callers say which ones they accept."""
    request = urllib.request.Request(url, method=method,
                                     data=body.encode() if isinstance(body, str) else body)
    if content_type:
        request.add_header("Content-Type", content_type)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def get_json(url):
    status, text = http(url)
    if status != 200:
        raise RuntimeError(f"{url} returned {status}")
    return json.loads(text)


def resolve_plan(suite, plan, clone_from):
    """The plan to run. Cloning copies an existing plan's config, which is where the harness CA and the
    credential signing key live, so a fresh plan needs no key material handling here."""
    if plan:
        return plan, get_json(f"{suite}/api/plan/{plan}")

    source = get_json(f"{suite}/api/plan/{clone_from}")
    variant = urllib.parse.quote(json.dumps(source["variant"]))
    status, text = http(f"{suite}/api/plan?planName={source['planName']}&variant={variant}",
                        method="POST", body=json.dumps(source["config"]), content_type="application/json")
    if status not in (200, 201):
        raise RuntimeError(f"cloning plan {clone_from} returned {status}: {text[:200]}")
    created = json.loads(text)
    print(f"created plan {created['id']} from {clone_from}")
    # The create response carries the modules but not the description, so keep the source's.
    return created["id"], created | {"description": source.get("description")}


def screenshot(chrome, url, path):
    subprocess.run([chrome, "--headless", "--disable-gpu", "--no-sandbox", "--ignore-certificate-errors",
                    "--hide-scrollbars", "--window-size=1100,1100", f"--screenshot={path}", url],
                   capture_output=True, timeout=120, check=True)


def upload_evidence(suite, test_id, path):
    """Attach the screenshot to the module's upload placeholder. The suite wants a bare data URI with no
    trailing newline; anything else comes back as 'Only jpeg/png files accepted' or a decode error."""
    log = get_json(f"{suite}/api/log/{test_id}")
    placeholder = next((entry["upload"] for entry in log if entry.get("upload")), None)
    if placeholder is None:
        return "none requested"

    data_uri = "data:image/png;base64," + base64.b64encode(open(path, "rb").read()).decode()
    status, text = http(f"{suite}/api/log/{test_id}/images/{placeholder}",
                        method="POST", body=data_uri, content_type="text/plain")
    if status != 200:
        raise RuntimeError(f"uploading evidence for {test_id} returned {status}: {text[:200]}")
    return "uploaded"


def await_finish(suite, test_id, attempts=20, delay=10):
    for _ in range(attempts):
        info = get_json(f"{suite}/api/info/{test_id}")
        if info.get("status") in ("FINISHED", "INTERRUPTED"):
            return info["status"], info.get("result")
        time.sleep(delay)
    return "WAITING", get_json(f"{suite}/api/info/{test_id}").get("result")


def run_module(args, module):
    test_id = json.loads(http(
        f"{args.suite}/api/runner?test={module}&plan={args.plan_id}"
        f"&variant={urllib.parse.quote(json.dumps(MODULE_VARIANT))}", method="POST")[1])["id"]
    time.sleep(1)

    # The only value scraped from HTML. Everything after this reads the session's own JSON.
    page = http(f"{args.harness}/verify/start")[1]
    found = re.search(r"/verify/([A-Za-z0-9_-]{16,})", page)
    if not found:
        raise RuntimeError(f"{args.harness}/verify/start produced no session id")
    session_id = found.group(1)

    authorization_uri = get_json(f"{args.harness}/verify/{session_id}")["authorizationRequestUri"]
    status, _ = http(authorization_uri)
    if status not in (200, 302, 303, 307):
        raise RuntimeError(f"the suite answered the authorization request with {status}")
    time.sleep(2)

    # Hitting the endpoint satisfies the protocol but not the suite's "paste the authorization URI"
    # interaction, and without closing that the module never leaves WAITING.
    http(f"{args.suite}/api/runner/browser/{test_id}/visit"
         f"?url={urllib.parse.quote(authorization_uri, safe='')}", method="POST")

    session = get_json(f"{args.harness}/verify/{session_id}")
    result = session.get("result")

    # A module leaves WAITING once its evidence is in, so only an evidence run has something to wait
    # for. A regression run reads the verdict straight off the session and moves on.
    evidence = "skipped"
    if args.evidence:
        path = f"{args.evidence_dir}/{module}.png"
        screenshot(args.chrome, f"{args.harness}/evidence/{session_id}", path)
        evidence = upload_evidence(args.suite, test_id, path)
        suite_status, suite_result = await_finish(args.suite, test_id)
    else:
        info = get_json(f"{args.suite}/api/info/{test_id}")
        suite_status, suite_result = info.get("status"), info.get("result")
    return {"module": module, "testId": test_id, "session": session_id, "result": result,
            "evidence": evidence, "suiteStatus": suite_status, "suiteResult": suite_result}


def check(outcome):
    """What the run has to show for each module, as a reason or None when it is right."""
    expectation = EXPECTED[outcome["module"]]
    result = outcome["result"]

    if expectation is SUITE_DECIDES:
        return None if outcome["suiteResult"] in ("SKIPPED", "PASSED", "REVIEW") \
            else f"suite reported {outcome['suiteResult']}"

    if result is None:
        return "the harness recorded no verification result"
    if expectation is ACCEPT and not result["isValid"]:
        return f"expected accept, got {[e['code'] for e in result['errors']]}"
    if expectation is REJECT and result["isValid"]:
        return "expected reject, the presentation was accepted"
    if expectation is ACCEPT and not result["disclosedClaims"]:
        # The failure this check exists for: ask for a claim the suite's credential does not carry and it
        # sends a valid presentation disclosing nothing. The module still verifies and the evidence page
        # reads "No claims disclosed", which is not what the positive modules ask you to show.
        return "accepted but disclosed nothing; see Request:Claim in README.md"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--plan", help="run this existing plan")
    source.add_argument("--clone-plan", help="create a fresh plan from this one's configuration and run that")
    parser.add_argument("--suite", default="https://localhost:8443")
    parser.add_argument("--harness", default="https://localhost:5099")
    parser.add_argument("--evidence", action="store_true", help="screenshot and upload, completing the plan")
    parser.add_argument("--evidence-dir", default="/tmp")
    parser.add_argument("--chrome", default="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    parser.add_argument("--json", help="write the full outcome here")
    args = parser.parse_args()

    args.plan_id, plan = resolve_plan(args.suite, args.plan, args.clone_plan)
    modules = [m["testModule"] for m in plan["modules"]]

    unknown = [m for m in modules if m not in EXPECTED]
    if unknown:
        sys.exit(f"unknown module(s), add them to EXPECTED before trusting a result: {', '.join(unknown)}")
    if args.evidence:
        subprocess.run([args.chrome, "--version"], capture_output=True, check=True)

    print(f"plan {args.plan_id}: {plan.get('description') or plan.get('planName')}")
    print(f"{len(modules)} modules, harness at {args.harness}\n")

    outcomes, failures = [], []
    for module in modules:
        outcome = run_module(args, module)
        reason = check(outcome)
        outcomes.append(outcome | {"problem": reason})
        if reason:
            failures.append((module, reason))
        verdict = "-" if outcome["result"] is None else ("accept" if outcome["result"]["isValid"] else "reject")
        print(f"{'FAIL' if reason else 'ok':4s}  {verdict:7s} {outcome['suiteStatus']:11s} "
              f"{outcome['suiteResult'] or '-':8s} {module[22:]}", flush=True)

    if args.json:
        json.dump(outcomes, open(args.json, "w"), indent=1)

    print()
    if failures:
        for module, reason in failures:
            print(f"FAIL {module}: {reason}")
        sys.exit(1)
    print(f"all {len(modules)} modules behaved as expected")


if __name__ == "__main__":
    main()

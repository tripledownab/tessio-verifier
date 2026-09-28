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
import datetime
import http.client as http_client
import json
import pathlib
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The two ends name the same variant differently. A suite plan's credential_format is sd_jwt_vc or
# iso_mdl, and the harness's Request:CredentialFormat is the OpenID4VP format identifier, so comparing
# the strings directly reports a mismatch on a CORRECT pairing. One mapping, here, because a second copy
# is free to drift from this one and the preflight is the only caller.
HARNESS_FORMAT = {"sd_jwt_vc": "dc+sd-jwt", "iso_mdl": "mso_mdoc"}

# The same split for the response mode: the plan's variant against the harness's ResponseMode enum name.
# A mismatch fails every module with "the harness recorded no verification result", which reads like a
# verifier bug and is a configuration one.
HARNESS_RESPONSE_MODE = {"direct_post": "DirectPost", "direct_post.jwt": "DirectPostJwt"}

# What /config must carry to be this harness's. A server answering JSON without them is something else
# on the port, and the preflight says so rather than failing on a missing key.
HARNESS_CONFIG_KEYS = {"credentialFormat", "responseMode", "authorizationEndpoint", "srcTree", "exportOf", "instance"}
# Build stamps a harness may legitimately lack: a working-tree build has no exportOf, an export no srcTree.
HARNESS_OPTIONAL_STAMPS = {"srcTree", "exportOf"}

# This script's own directory. Everything git is asked is asked of the checkout the script lives in,
# never the current directory: run from elsewhere, the current directory is another tree or no tree.
HERE = pathlib.Path(__file__).resolve().parent

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


class Unavailable(Exception):
    """The service behind a gateway is gone, although the gateway itself still answers."""


# What the suite's nginx returns when the server container behind it has stopped. Treated as the service
# being unreachable rather than as a protocol answer, because nginx staying up while the server dies is
# how the suite fails, and a 502 counted as "answering" once let a dead suite pass the preflight.
GATEWAY_DOWN = {502, 503, 504}


def http(url, method="GET", body=None, content_type=None, timeout=90):
    """The status and body, for any status a service itself sends. Callers say which ones they accept.

    Raises Unavailable for a gateway reporting the service gone, and lets OSError and
    http.client.HTTPException through for a connection that never formed, broke or was cut short. The
    gateway decision has one owner, here. The preflight turns each of these into a message naming the
    end, and a mid-run failure is diagnosed by asking both ends rather than by its type."""
    request = urllib.request.Request(url, method=method,
                                     data=body.encode() if isinstance(body, str) else body)
    if content_type:
        request.add_header("Content-Type", content_type)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            status, text = response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        status, text = error.code, error.read().decode("utf-8", "replace")
    if status in GATEWAY_DOWN:
        raise Unavailable(f"{url} returned {status}")
    return status, text


def get_json(url):
    status, text = http(url)
    if status != 200:
        raise RuntimeError(f"{url} returned {status}")
    return json.loads(text)


def healthy(url):
    """Whether the service answers this URL with 200. Anything else, a refused or broken connection, a
    gateway error or a server error, counts as unhealthy. Used only to explain a failure after the fact,
    so it never raises."""
    try:
        return http(url, timeout=10)[0] == 200
    except (OSError, Unavailable, http_client.HTTPException):
        return False


def docker_hint():
    """Why the suite might be silent, when the docker CLI is here to say. Adds nothing where there is no
    docker CLI to ask, because this is advice appended to an error that is already being reported."""
    try:
        done = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if done.returncode != 0:
        return (" The Docker daemon is not answering either, so start Docker Desktop first and wait "
                "for it, then bring the suite up with docker compose -f docker-compose-prebuilt.yml up -d.")
    return (" The Docker daemon is up, so check the suite's containers are all running: "
            "docker compose -f docker-compose-prebuilt.yml up -d.")


def refuse_plain_http(name, url):
    """Both ends serve https only, so an http URL cannot reach either. Said first and alone, because the
    symptom is "not answering", and a reader told that restarts a process that is running fine."""
    if url.startswith("http:"):
        sys.exit(f"--{name} is {url}, and the {name} serves https only. Use https://.")


def fetch_source_plan(args):
    """The plan to run or clone, or an exit that names why it cannot be read. This is also the suite's
    health check: it needs the server AND its database, which the suite's front page does not."""
    plan_id = args.plan or args.clone_plan
    refuse_plain_http("suite", args.suite)
    try:
        status, text = http(f"{args.suite}/api/plan/{plan_id}", timeout=30)
    except (OSError, Unavailable, http_client.HTTPException) as error:
        sys.exit(f"the conformance suite is not answering at {args.suite} "
                 f"({getattr(error, 'reason', error)}).{docker_hint()}")
    if status == 404:
        sys.exit(f"the suite has no plan '{plan_id}'. Check the id against the suite's plan list.")
    if status != 200:
        sys.exit(f"the suite answered {status} for plan '{plan_id}', so it is up but not healthy. "
                 f"A stopped database container does this.{docker_hint()}")
    return json.loads(text)


def fetch_harness_config(args):
    """The RUNNING harness's settings, or an exit that names why they cannot be read."""
    refuse_plain_http("harness", args.harness)
    try:
        status, text = http(f"{args.harness}/config", timeout=10)
    except (OSError, Unavailable, http_client.HTTPException) as error:
        sys.exit(f"the harness is not answering at {args.harness} ({getattr(error, 'reason', error)}). "
                 "Start it in tools/conformance-harness with dotnet run, wait "
                 "for it to listen, and check appsettings.Local.json names this port.")
    if status == 404:
        sys.exit(f"whatever answers at {args.harness} has no /config: either a harness built before these "
                 "checks existed, or not the harness at all. Stop what holds the port and start the harness "
                 "from this checkout.")
    try:
        config = json.loads(text) if status == 200 else None
    except json.JSONDecodeError:
        config = None
    if (not isinstance(config, dict) or not HARNESS_CONFIG_KEYS <= config.keys()
            or not all(isinstance(config[k], str) for k in HARNESS_CONFIG_KEYS - HARNESS_OPTIONAL_STAMPS)
            or not all(isinstance(config[k], (str, type(None))) for k in HARNESS_OPTIONAL_STAMPS)):
        sys.exit(f"{args.harness}/config answered {status} but not with this harness's settings, so "
                 "something else holds the port or the harness is older than this script. Stop it and "
                 "start the harness from this checkout.")
    return config


def src_tree():
    """This checkout's src/ tree as it is on disk, by the same script the harness build stamps with."""
    return subprocess.run(["sh", str(HERE / "src-tree.sh")], capture_output=True, text=True,
                          check=True).stdout.strip()


def preflight(args):
    """Every precondition, BEFORE anything is created. Returns the source plan, the harness's config, and
    the src/ tree the harness was built from.

    The order is the whole point. This script used to clone a plan first, so a harness that was not
    running left a plan behind in the suite, then died on a traceback naming neither end. Each check
    below names a way a run fails, or passes, for a reason that is not the code under test."""
    plan = fetch_source_plan(args)

    # The plan lists its modules before it is cloned, so an unknown one is refused while nothing exists.
    unknown = [m["testModule"] for m in plan["modules"] if m["testModule"] not in EXPECTED]
    if unknown:
        sys.exit(f"unknown module(s), add them to EXPECTED before trusting a result: {', '.join(unknown)}")
    if args.evidence and not pathlib.Path(args.chrome).is_file():
        sys.exit(f"--evidence needs Chrome for screenshots, and there is none at {args.chrome}. Pass --chrome.")

    harness = fetch_harness_config(args)

    # The variant, the response mode and the alias each fail every module for the wrong reason when they
    # disagree. Both ends state all three, so compare them rather than trusting whichever
    # appsettings.Local.json was copied in last. A plan missing one is refused, not waved past.
    variant = plan.get("variant") or {}
    for key, mapping, have in (("credential_format", HARNESS_FORMAT, harness["credentialFormat"]),
                               ("response_mode", HARNESS_RESPONSE_MODE, harness["responseMode"])):
        wanted = variant.get(key)
        if wanted not in mapping:
            sys.exit(f"the plan's {key} is {wanted!r}, which this script does not map, so there is nothing "
                     "to check the harness against. Add it to the mapping rather than skipping the check.")
        if have != mapping[wanted]:
            sys.exit(f"{key} mismatch: the plan runs '{wanted}', which needs a harness on '{mapping[wanted]}',"
                     f" and this harness is on '{have}'. Copy the matching appsettings.Local.json in, restart"
                     f" the harness, and read {args.harness}/config.")
    alias = (plan.get("config") or {}).get("alias")
    if not alias or f"/test/a/{alias}/" not in harness["authorizationEndpoint"]:
        sys.exit(f"the plan's alias is {alias!r} and the harness sends wallets to "
                 f"{harness['authorizationEndpoint']}, which is another alias's endpoint.")

    # THE STALE HARNESS THAT MATTERS MOST passes every check above: the same variant, left running since
    # the code changed, or built from another checkout, or from edits reverted through git. It answers
    # every endpoint correctly with other bytes underneath.
    export_of = harness["exportOf"]
    if export_of:
        # Built by serve-export.sh from `git archive` of this commit, so its src/ IS that commit's.
        try:
            built = git(HERE, "rev-parse", f"{export_of}:src")
        except subprocess.CalledProcessError:
            sys.exit(f"the harness was exported from {export_of[:12]}, which this repository does not "
                     "have. Fetch it, or start the harness again with serve-export.sh from this checkout.")
    else:
        built = harness["srcTree"]
        if not built:
            sys.exit("the harness carries no build stamp, which happens on a Windows build or one older "
                     "than this script, so it cannot be told apart from a stale one. Rebuild it on macOS or "
                     "Linux from this checkout.")

    if args.record:
        # A RECORDING needs a harness built from a clean export. A working-tree build is stamped with
        # git's view of the source, and the compiler can read bytes that view does not describe: files
        # git ignores, a revert that kept an old timestamp, a save during the build, a build file from
        # above the checkout. An export has none of those, so its tree is HEAD:src by construction.
        if not export_of:
            sys.exit("a recording needs a harness built from a clean export of HEAD, and this one was built "
                     "from the working tree. Stop it and start it with: sh serve-export.sh "
                     "<appsettings.Local.json for the variant>")
        refusal = record_refusal(built, git(HERE, "rev-parse", "HEAD:src"))
        if refusal:
            sys.exit(refusal)
    else:
        # A regression run tests the working copy, so compare the build with the tree on disk. The build
        # stamps git's view of src/, and this computes the same view with the same script. It is not a
        # hash of what the compiler read: tools/conformance-harness/README.md lists the gaps.
        here = src_tree()
        if built != here:
            sys.exit(f"stale harness: it was built from src tree {built[:12]} and src/ here is {here[:12]}. It "
                     "predates a change, or was built from another checkout or from edits since reverted. "
                     "Stop it, confirm the port is free, and start it again from this checkout.")
    return plan, harness, built


def resolve_plan(suite, plan, clone_from, source):
    """The plan to run. Cloning copies an existing plan's config, which is where the harness CA and the
    credential signing key live, so a fresh plan needs no key material handling here."""
    if plan:
        return plan, source

    variant = urllib.parse.quote(json.dumps(source["variant"]))
    status, text = http(f"{suite}/api/plan?planName={source['planName']}&variant={variant}",
                        method="POST", body=json.dumps(source["config"]), content_type="application/json")
    if status not in (200, 201):
        raise RuntimeError(f"cloning plan {clone_from} returned {status}: {text[:200]}")
    created = json.loads(text)
    print(f"created plan {created['id']} from {clone_from}")
    # The create response carries the modules but neither the description nor the variant, so keep the
    # source's. The variant is what --record keys on, and it was sent in the query string above, so
    # copying it here describes the created plan rather than guessing at it.
    return created["id"], created | {"description": source.get("description"),
                                     "variant": source.get("variant")}


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


# Written into the record so whoever opens it after a failed release knows what it is for without
# finding this script first.
RECORD_NOTE = ("Generated by tools/conformance-harness/run-plan.py --record, on a clean run only. "
               "tools/check-conformance-record.py refuses a release whose src tree is not listed here. "
               "Do not hand-edit: an entry written by anything but a watched run is a false pass.")


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True,
                          check=True).stdout.strip()


def record_refusal(tested_tree, head_tree):
    """Why a run against tested_tree may not be recorded, or None. One owner for the rule, asked early by
    the preflight so a doomed --record run creates nothing, and again at record time."""
    if tested_tree != head_tree:
        return (f"the harness runs src tree {tested_tree[:12]} and HEAD:src is {head_tree[:12]}, so a record "
                "would name bytes the suite did not test. Commit, restart the harness from this checkout, "
                "then run with --record.")
    return None


def record_run(path, plan_id, plan, module_count, tested_tree):
    """Stamp a passing run into the release gate's record, keyed by credential format.

    Keyed by the git TREE of src/, not by the commit, because the version bump and this record are both
    commits that change nothing a wallet can observe. The tree is the id of the shipped content, so it
    answers "did the suite see these exact bytes" without caring what the commit graph did in between.
    """
    root = git(HERE, "rev-parse", "--show-toplevel")

    # THE ONE CHECK THAT MAKES THE RECORD TRUE. The record says "the suite ran HEAD:src", and the
    # harness's build stamp says which src/ tree it actually ran, uncommitted edits included. Record only
    # when they are the same tree. This replaced a check that src/ was clean at record time, which asked
    # the wrong tree at the wrong moment: a harness built from edits that were then reverted, or built in
    # another checkout, passed it while running bytes HEAD:src does not name.
    head_tree = git(root, "rev-parse", "HEAD:src")
    refusal = record_refusal(tested_tree, head_tree)
    if refusal:
        sys.exit(refusal)

    variant = (plan.get("variant") or {}).get("credential_format")
    if not variant:
        sys.exit("this plan declares no credential_format variant, so the run cannot be recorded")

    props = pathlib.Path(root, "Directory.Build.props").read_text(encoding="utf-8")
    version = re.search(r"<Version>([^<]+)</Version>", props)

    file = pathlib.Path(path)
    document = json.loads(file.read_text(encoding="utf-8")) if file.exists() else {}
    document["// NOTE"] = RECORD_NOTE
    document.setdefault("runs", {})[variant] = {
        "srcTree": head_tree,
        "commit": git(root, "rev-parse", "HEAD"),
        # Informational. The gate does NOT compare it, because a pure version bump ships identical
        # source and re-running the suite for it would test nothing.
        "version": version.group(1) if version else None,
        "planId": plan_id,
        "modules": module_count,
        "ranAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
    }
    file.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"recorded {variant} against src tree {document['runs'][variant]['srcTree'][:12]} in {path}")


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
    parser.add_argument("--record", help="on a clean run, stamp this variant into the release gate's record")
    args = parser.parse_args()

    source_plan, harness, tested_tree = preflight(args)
    args.plan_id, plan = resolve_plan(args.suite, args.plan, args.clone_plan, source_plan)
    modules = [m["testModule"] for m in plan["modules"]]

    print(f"plan {args.plan_id}: {plan.get('description') or plan.get('planName')}")
    print(f"{len(modules)} modules, harness at {args.harness}\n")

    outcomes, failures = [], []
    for module in modules:
        # The harness can be restarted or reconfigured between modules, deliberately or by a watcher.
        # Every setting the preflight checked, and the per-process instance id, must be what they were:
        # a restart loses sessions, and another build or config makes the run describe two harnesses.
        now = fetch_harness_config(args)
        if now != harness:
            changed = sorted(k for k in harness.keys() | now.keys() if harness.get(k) != now.get(k))
            sys.exit(f"the harness changed during the run, before {module[22:]}: {', '.join(changed)}. "
                     "Nothing was recorded. Run again.")
        try:
            outcome = run_module(args, module)
        except Exception:
            # Diagnose by asking both ends, not by exception type. An end dying mid-run surfaces as a
            # refused connection, a gateway error, a server error from a stopped database, a truncated
            # read or an unexpected 404, and no list of types covers them all. If both ends are healthy
            # the failure is a real one in this script or the code, so it is raised as it is.
            suite_ok = healthy(f"{args.suite}/api/plan/{args.plan_id}")
            harness_ok = healthy(f"{args.harness}/config")
            if suite_ok and harness_ok:
                # Healthy now is not the same as untouched: a harness restarted INSIDE the module comes
                # back healthy and has lost the session, which fails as an unknown session id. Only when
                # it is the same process as before is the failure a real one.
                if fetch_harness_config(args)["instance"] != harness["instance"]:
                    sys.exit(f"the harness restarted during {module[22:]} and lost its session. Nothing "
                             "was recorded. Run again without restarting it.")
                raise
            sys.exit(f"an end went down during {module[22:]}.\n"
                     f"  suite   {args.suite}: {'healthy' if suite_ok else 'NOT HEALTHY.' + docker_hint()}\n"
                     f"  harness {args.harness}: {'healthy' if harness_ok else 'DOWN, restart it with dotnet run'}\n"
                     f"Nothing was recorded, because --record runs after every module passes. Fix it and "
                     f"run the same command again.")
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

    # After the verdict, never before it. A record written ahead of the failure check would survive a
    # run that failed, which is the whole thing the gate exists to prevent.
    if args.record:
        record_run(args.record, args.plan_id, plan, len(modules), tested_tree)


if __name__ == "__main__":
    main()

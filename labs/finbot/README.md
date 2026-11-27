# The FinBot guided lab

The FinBot lab runs on your own computer and shows ACS stopping attacks on an AI agent. FinBot is a finance agent built to be attacked. In seven modules you run each attack with ACS off, then again with a Guardian deciding every step, and watch each decision arrive in a viewer in your browser.

You don't need a model key or a cloud account. The model's answers come from recordings that ship with the lab. <!-- claim:C-08 -->

## Try it first

These commands download the lab, start it, and run one attack with ACS on. Run them in a terminal, one at a time.

```sh
git clone https://github.com/GenAI-Security-Project/agent-control-standard.git
cd agent-control-standard/labs/finbot
./lab.sh doctor
./lab.sh init
./lab.sh up
./lab.sh viewer
```

The last command prints an address, `http://localhost:8095/` unless you changed the port. Open it in your browser and leave the tab open, because the viewer only shows rows that arrive while the page is open.

Now turn ACS on and run the attack, a chat that asks FinBot to mail vendor data to an outside address:

```sh
./lab.sh mode enforce
./lab.sh run s2
```

In the viewer, the headline turns to "Deny: the call never runs" on the `finmail__send_email` row. The terminal ends with a line like this one:

```text
DONE: s2 ran in enforce mode and FinBot went quiet. Run record state/runs/20261209T120000Z-s2.json
```

That deny is the Guardian refusing the outside email before FinBot could send it. The modules explain what you just saw, one control at a time.

## What you need

- Git, to download the lab.
- Docker. On macOS that's Docker Desktop. On Linux it's Docker Engine with the Compose v2 plugin. Windows is untested. <!-- claim:C-16 -->
- At least 6 GiB of memory for Docker. On macOS, set it in Docker Desktop under Settings, Resources.
- About 5 GB of free disk space. The lab's images take a little over 2 GB, and building them needs room beside them.
- A computer with an x86_64 or arm64 processor. Apple silicon Macs are arm64.
- Ports 8090, 8095 and 8097 free on your computer. The lab uses them for the approver page, the decision viewer and FinBot's web page.
- A web browser.

`./lab.sh doctor` checks all of these and prints one line for each. A line that starts with DONE is fine. A line that starts with NOT YET says what to fix. Fix it and run `doctor` again before you go on.

The first `./lab.sh up` downloads or builds the lab's images, so it takes several minutes. Later starts take seconds.

## The seven modules

Each module is a page you follow in order. Open it, run the commands it shows, and finish with its check, `./lab.sh check N`, which prints DONE when your runs show what the module teaches.

| Module | What you see |
|---|---|
| [1. Wire it in](modules/1.md) | FinBot onboards a vendor with ACS off, then with every tool call checked and every answer signed |
| [2. Watch it](modules/2.md) | A chat tricks FinBot into mailing data out. Shadow mode records a deny but blocks nothing |
| [3. Stop it](modules/3.md) | You finish a policy that blocks outside mail and lets the vendor's own mail through |
| [4. Ask a human](modules/4.md) | A large payment waits for an approver, who approves it once and rejects it once |
| [5. Clean it](modules/5.md) | The Guardian redacts a bank account number before the model reads it |
| [6. Poison a tool](modules/6.md) | A changed tool description is caught by its pinned digest |
| [7. Forge a decision](modules/7.md) | A forged decision passes under a shared HMAC key and fails under ML-DSA-65 <!-- claim:C-04 --> |

If you only want to see ACS work, module 1 is enough. Modules 3 to 6 each ask you to finish a policy, and each comes with a solution you can put in place with `./lab.sh policy N solution`.

## Words you'll meet

FinBot never talks to the Guardian. A gateway sits between FinBot and its model, asks the Guardian about every tool call, and applies the answer. The Guardian is the service that decides. Its answer is a decision: allow, deny, modify or ask.

The gateway has three modes. Off asks the Guardian nothing. Shadow asks and records, but applies nothing. Enforce applies every decision. `./lab.sh mode off`, `shadow` or `enforce` switches between them.

The decision viewer is the page `./lab.sh viewer` opens. It shows each step, the decision, and whether the decision's signature checks out.

The [glossary](modules/glossary.md) defines every term the modules use.

## When something goes wrong

- A port is in use. Set a different one in `labs/finbot/.env`, for example `LAB_PORT_VIEWER=8195`, then run `doctor` again.
- `doctor` says Docker has too little memory. Raise it to 6 GiB or more and restart Docker.
- `init` prints "NOT YET: lab is already initialized". That's fine. Your lab is already set up, so go on to `up`. Don't add `--force`, because it replaces the lab's keys.
- The viewer shows nothing after a run. It only shows rows that arrive while the page is open. Reload it, then run the scenario again.

To stop the lab and keep your progress, run `./lab.sh down`. To start over from nothing, run `./lab.sh reset`.

## Use your own model

Replay is the default and needs nothing extra. To send FinBot's model calls to OpenAI instead, bring your own OpenAI API key. The lab ships with no key. Save yours in `labs/finbot/state/secrets/openai.key`, readable only by you (`chmod 600`), and run `./lab.sh upstream openai`. Git ignores everything under `state/`, so the key never reaches a commit, and model calls bill to your account. A live model's answers differ from the recordings, so a module's check may not pass the same way. `./lab.sh upstream replay` switches back.

## What the lab doesn't claim

The [claims ledger](CLAIMS.md) lists every claim the lab makes, the evidence behind each one, and what the lab doesn't claim. Read it before you quote the lab anywhere.

## Where to go next

- [Run a Guardian](https://owaspacs.org/docs/topics/reference-implementations/) with your own coding agent.
- [Core concepts](https://owaspacs.org/docs/topics/core_concepts/) explains ACS beyond the lab.
- Questions go to [GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions) or `#team-genai-asi-acs-general` on the OWASP Slack. A bug in the lab goes in the [issue tracker](https://github.com/GenAI-Security-Project/agent-control-standard/issues).

# Lab glossary

Each term the module guides use, in plain words. A guide links a term here the first time it uses it.

## ACS

The OWASP Agent Control Standard. It says how an AI agent checks with a separate service, the Guardian, before it acts. ACS off means the gateway asks the Guardian nothing.

## Agent

An AI program that reads a request, decides what to do, and calls tools to do it. In this lab the agent is FinBot.

## FinBot

A finance assistant built to be attacked, from the OWASP GenAI Security Project's capture-the-flag game. It onboards vendors, pays invoices and sends email through its own tools. The lab runs FinBot's code unchanged and changes four of its settings. <!-- claim:C-01 -->

## Dead drop

FinBot's mailbox for outside mail. Mail to a registered vendor goes to that vendor's inbox, and company mail goes to the admin inbox. Mail to any other address lands in the dead drop. Each run saves the dead drop in its run record, and the module 2 check counts the messages that arrived during the run.

## Gateway

The ACS piece between FinBot and its model. It reads each tool call the model asks for, asks the Guardian about it, and applies the answer. FinBot reaches the model only through the gateway. <!-- claim:C-17 -->

## Guardian

The service that decides. The gateway sends it each governed step, and it answers with a decision. It lives on a network FinBot can't reach, so FinBot can't bypass it. <!-- claim:C-17 -->

## Policy

The rules the Guardian applies, written in Rego and run by OPA. Modules 3 to 6 each ship a starter policy and a solution. `./lab.sh policy` puts either one live.

## OPA

Open Policy Agent, the engine that runs the lab's policy. The Guardian asks OPA for a verdict on each governed step. The OPA input and verdict shapes are a lab convention until issue #531 settles them. <!-- claim:C-13 -->

## Rego

OPA's policy language. A Rego rule reads the step the gateway sent and returns allow, deny, modify or ask.

## Hook

A point where an ACS agent stops and asks the Guardian before it acts. ACS defines nineteen hooks. The lab governs two of them live: `steps/toolCallRequest` and `steps/toolCallResult`. <!-- claim:C-06 -->

## Tool call

A request from the model to run one of FinBot's tools, such as sending an email. The gateway sends each one to the Guardian as `steps/toolCallRequest` before FinBot runs it. <!-- claim:C-06 -->

## Tool result

What a tool hands back after it runs, such as a vendor's details. The gateway sends it to the Guardian as `steps/toolCallResult` before the model reads it. <!-- claim:C-06 -->

## Decision

The Guardian's answer about one step. Allow lets the step go ahead. Deny stops it. Modify changes it first, for example by redacting one field.

Ask holds the step until a person approves or rejects it on the approver page. No answer within 240 seconds counts as a reject. The answer field the approver page sends is a lab convention until issue #175 settles it. <!-- claim:C-13 -->

## Shadow mode

The gateway asks the Guardian and records each decision, then forwards the traffic unchanged. A deny in shadow mode stops nothing. It shows what enforce mode would have stopped. <!-- claim:C-09 -->

## Enforce mode

The gateway applies every decision. In enforce mode the lab fails closed, so the gateway denies a step it can't get a decision for. <!-- claim:C-09 -->

The v0.1.0 specification still defaults to proceed on a decision failure. The change to deny waits on issue #32. <!-- claim:C-14 -->

## Transcript

The gateway's record of one session with the Guardian, under `state/transcripts/`. It holds every request the gateway sent and every answer it got, one JSON line each.

## Audit log

The gateway's running log of what happened, one JSON line per event. It notes each session it opened, each decision it applied, each ask a person answered, and each replay miss.

## Model input log

Every request the gateway forwarded to the model, one line each, in `state/model-inputs.jsonl`. `./lab.sh model-log` prints the newest one, so you can read exactly what the model read.

## Replay

The lab's default model source. The gateway answers FinBot from recorded model answers, so the lab runs with no model key and no network. <!-- claim:C-08 -->

A request the recordings don't cover gets a fixed neutral reply, and the viewer marks it. Replay serves what was recorded. It isn't a live model. <!-- claim:C-08 -->

## Epoch

A counter the gateway keeps. Bumping it closes every open session with `steps/sessionEnd`, and the next request starts a fresh one. So each run gets its own session. The lab bumps it after each mode, signing, upstream or policy change, and before each scenario. <!-- claim:C-06 -->

## HMAC

A signature made with a key both sides share. The gateway and the Guardian share one, so either side could have written any message carrying it. Anyone holding that key can forge a Guardian allow. <!-- claim:C-04 -->

Requests from the gateway always carry HMAC-SHA256. Decisions carry it too unless the lab signs them with ML-DSA-65. <!-- claim:C-02 -->

## ML-DSA-65

A post-quantum signature scheme from FIPS 204. When the lab signs decisions with it, only the Guardian holds the private key. <!-- claim:C-02 -->

Anyone holding the Guardian's public key can check a decision but can't make one. That holds only when the public key reached you over a channel the forger doesn't control. <!-- claim:C-03 -->

## Key document

The file that carries the Guardian's public key, `state/keys/guardian-keys.json`. Its format is a lab convention until issue #460 settles how keys get published. <!-- claim:C-13 -->

## Fingerprint

A short hash of the Guardian's public key, written `sha256:` and 64 hex digits. `./lab.sh init` prints it and writes it to `.env`. The gateway, the Guardian and the viewer can't read that file, because it isn't mounted into their containers. `./lab.sh verify` refuses a key document whose key doesn't match it. <!-- claim:C-03 -->

## Signature

Bytes attached to a message that show a key holder wrote it and nobody changed it since. Requests always carry an HMAC signature. Decisions carry HMAC or ML-DSA-65. <!-- claim:C-02 -->

## Forgery<!-- claim:C-04 -->

A decision that looks like the Guardian's but that someone else wrote. In module 7 you forge an allow into a copy of a transcript. <!-- claim:C-04 -->

Under HMAC the forgery checks out, because the gateway holds the shared key. Under ML-DSA-65 it fails at the forged line. <!-- claim:C-04 --> <!-- claim:C-03 -->

## Downgrade

Talking a session down to a weaker signature, here from ML-DSA-65 back to HMAC. A Guardian signing with ML-DSA-65 refuses a session that doesn't offer it. <!-- claim:C-05 -->

The refusal covers the decision signature only. Full downgrade detection needs transcript binding, which waits on issue #13. <!-- claim:C-05 -->

## Tool digest

A hash of a tool's declaration: its name, description, parameters and strict setting. The gateway puts it in each tool call's `tool.version` field. <!-- claim:C-13 -->

The module 6 policy compares it with the digest pinned from a clean run, so a changed description gets a deny. The digest is a lab convention until issue #38 settles it. <!-- claim:C-13 -->

## Neutral deny line

The fixed sentence the model reads in place of a denied tool's output: "I couldn't complete that action." It's the one thing the agent sees when a control acts. <!-- claim:C-17 -->

A block is visible to the agent it stops, as with any enforcement point. The agent still can't bypass the Guardian. <!-- claim:C-17 -->

## Trust boundary

Checks read `state/`, so anything that can write `state/` can steer a check. A check believes the files it finds there, so a file planted there could fool it. It skips a run record that is a symlink.

The gateway can write `state/`, which is why the fingerprint lives in `.env` instead.

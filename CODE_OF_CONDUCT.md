# Code of Conduct

The Agent Control Standard (ACS) runs on volunteer time. This code protects the people who give that time and the attention they spend here.

It has two parts, and both apply to everyone, leads included. Part 1 covers how we treat each other, and OWASP handles reports under it. Part 2 covers how work enters this repository, and the project leads enforce it.

## Part 1: How We Treat Each Other

Part 1 is the Contributor Covenant, version 1.4.

### Our Pledge

In the interest of fostering an open and welcoming environment, we as contributors and maintainers pledge to making participation in our project and our community a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

* Using welcoming and inclusive language  
* Being respectful of differing viewpoints and experiences  
* Gracefully accepting constructive criticism  
* Focusing on what is best for the community  
* Showing empathy towards other community members

Examples of unacceptable behavior by participants include:

* The use of sexualized language or imagery and unwelcome sexual attention or advances  
* Trolling, insulting/derogatory comments, and personal or political attacks  
* Public or private harassment  
* Publishing others' private information, such as a physical or electronic address, without explicit permission  
* Other conduct which could reasonably be considered inappropriate in a professional setting

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable behavior and are expected to take appropriate and fair corrective action in response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or reject comments, commits, code, wiki edits, issues, and other contributions that are not aligned to this Code of Conduct, or to ban temporarily or permanently any contributor for other behaviors that they deem inappropriate, threatening, offensive, or harmful.

### Scope

This Code of Conduct applies both within project spaces and in public spaces when an individual is representing the project or its community. Examples of representing a project or community include using an official project e-mail address, posting via an official social media account, or acting as an appointed representative at an online or offline event. Representation of a project may be further defined and clarified by project maintainers.

## Part 2: How Work Enters the Repository

Every pull request, issue, review, and comment asks a volunteer to read it. Tools now produce all four faster than anyone can read them, so reviewer attention is the scarce resource here.

Part 2 says how to ask for that attention. It enforces two entries in the [decision log](./docs/decisions/index.md): D-041, which limits review to assigned and accepted work, and D-042, which starts schema, hook, and event changes with a Discussion. [CONTRIBUTING.md](./CONTRIBUTING.md) explains the workflow.

### Answer for Your Account

Use any tool you like, AI included. [Authorship and AI assistance](./CONTRIBUTING.md#authorship-and-ai-assistance) in CONTRIBUTING.md already says so, and nothing here changes it.

What your account posts is yours. Read every pull request, issue, review, and comment before it goes out under your name. Be ready to explain your change without the tool, and answer plainly if a lead asks how you produced or tested it.

Nothing posts from your account unattended. A script or agent that opens pull requests, files issues, submits reviews, or comments without you approving each one breaks this code. The one exception is project automation, which means Dependabot and the workflows in `.github/workflows` that the project leads own.

### Start From an Assigned Issue

- A pull request that changes behavior, normative text, or code references an issue labeled `status:accepted` that a lead assigned to you before you opened the pull request.  
- A pull request opened early earns no assignment. If a lead wants the work anyway, the lead says so on the issue, assigns it, and you reopen.  
- An issue assigned to someone else is theirs. Offer help in a comment on the issue and wait for an answer.  
- A new idea starts as an issue, filed through one of the issue forms. A change to the schemas, the hook set, or the event catalog starts as a [Discussion](https://github.com/GenAI-Security-Project/agent-control-standard/discussions).  
- An editorial correction needs no issue: a typo, a grammar fix, a broken link, or a formatting repair that leaves the meaning untouched.

### Keep Your Queue Small

- Hold no more than three open pull requests at a time, drafts included.  
- Hold no more than two assigned issues at a time. Finish one or hand it back before you ask for another.  
- Post one item at a time. Leads treat five or more pull requests, issues, reviews, or comments from one account inside a minute as bulk activity.  
- A pull request that a lead has approved and not yet merged does not count against your limit.  
- A lead can raise a limit for a named contributor by saying so on the issue.

The two caps do not apply to leads working in their own workstream. Their merges that bypass a ruleset appear in the nightly Roadmap health issue, as [GOVERNANCE.md](./GOVERNANCE.md#triage-authority) describes.

### Review When Asked, and Show Your Work

- Approve or request changes only when the author or a lead asked for your review, or when you are a code owner for the changed paths.  
- Anyone may leave a comment review that reports a specific finding someone else can reproduce.  
- An approval names the commit you reviewed, what you ran, and what you did not check.  
- A summary of the diff is not a review.  
- Review one pull request at a time. Leads dismiss approvals posted in a batch.

An approval that meets the bar looks like this:

> Reviewed at `abc1234`. Ran `uv run pytest -v` and the adapter conformance gate for `claude`, and both pass. Did not run the NAT suite.

### Earn Roles Through Merged Work

Leads propose new leads, triage volunteers, and code owners, following [How leadership changes](./GOVERNANCE.md#how-leadership-changes) in GOVERNANCE.md. Those offers follow assigned work that merged and reviews that held up. Asking for a role does not speed that up, and neither does volume.

### What Leads Owe You

- Leads reply to a new issue within about a week.  
- A lead gives a reason and links the section every time the lead closes, dismisses, or hides something under Part 2\.  
- Leads meet the same review bar, so a lead's approval names the commit and what the lead ran.  
- No lead assigns an issue after the fact. A lead who wants work that already exists says so on the issue first.

## Enforcement

### OWASP Handles Part 1 Reports

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported through the [OWASP Code of Conduct reporting process](https://owasp.org/www-policy/operational/code-of-conduct). ACS is a project of the [OWASP GenAI Security Project](https://genai.owasp.org/), and conduct reports are handled by OWASP rather than by individual project maintainers, so that reports about a maintainer reach someone independent of them. All complaints will be reviewed and investigated and will result in a response that is deemed necessary and appropriate to the circumstances. Reporter confidentiality is maintained throughout. Further details of specific enforcement policies may be posted separately.

Project maintainers who do not follow or enforce the Code of Conduct in good faith may face temporary or permanent repercussions as determined by other members of the project's leadership.

### Project Leads Enforce Part 2

Any lead may close a pull request or an issue that falls outside Part 2, dismiss a review, or hide a comment, with a link to the section it breaks. A closure is not a penalty, and you are welcome back with work that fits.

Repeated or deliberate breaches follow three steps.

1. A project lead first gives notice, naming the rule and the evidence, in private where that is practical. Work outside the rules gets closed.  
2. A second breach within 90 days brings a restriction. The account is limited to one open pull request and no reviews for 30 days, and two project leads decide.  
3. A third breach within 12 months brings removal. Collaborator access ends, and for 90 days leads close and hide the account's new activity in the repository. Leads may also ask OWASP to block the account across the organization. Two project leads decide this step too.

Bulk activity that continues after a notice goes straight to removal, and so does a second account used to get around a restriction.

A notice lapses after 12 months without another breach. Project leads keep restrictions and removals in a private record, because the decision log leaves out account and permission details by its own rule.

To appeal, reply where the lead recorded the action, or message a project lead on OWASP Slack, within 14 days. A project lead who did not make the call reviews it and answers within 14 days.

Part 2 binds leads too, and when a lead breaches it, the project leads who were not involved decide. If you believe a lead is using Part 2 to harass or retaliate, that is a Part 1 matter, and it goes to OWASP.

Bulk automated activity can also breach section 4 of the [GitHub Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies), and leads may report it to GitHub.

## When This Takes Effect

Part 2 takes effect the day it merges. Contributors over a limit that day have 14 days to finish, close, or hand back work. After that, leads close pull requests with no assigned issue, oldest first, with an invitation to reopen once a lead assigns the work.

Leads review Part 2 at each milestone review, alongside the Current Priority Scope in CONTRIBUTING.md.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org), version 1.4, available at [https\://www\.contributor-covenant.org/version/1/4/code-of-conduct.html](https://www.contributor-covenant.org/version/1/4/code-of-conduct.html)

Part 2 is original to ACS. Its rule that a person approves everything an account posts follows the [LLVM AI Tool Use Policy](https://llvm.org/docs/AIToolPolicy.html).
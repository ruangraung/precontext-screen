# Security policy

## What this project is, in security terms

Precontext Screen sits on one hook in Hermes: after a tool has returned, and before its result
enters the model's context. It reads a slice of that result, asks a classifier whether the text
tries to steer the reader, and, when the answer comes back hostile, appends a banner that tells
the agent to treat the text as data.

Two consequences are worth stating plainly before the scope lists.

**The banner is a warning, not a boundary.** A model that ignores it can still act on the text it
was warned about. This project reduces the chance that an injection reaches a model unmarked. It
does not make injection impossible.

**The judgement comes from a third party.** The page slice is sent to TypeSafe Jev, which is the
only egress point in the design. If sending that slice is unacceptable for a given source, do not
screen that source.

## In scope

- Content reaching a destination other than the declared egress point, or a payload the plugin
  refused to send being sent after all.
- Page content, a payload, or a key appearing in the alert queue, the screen log, or any other
  file the plugin writes. Verdicts, hashes, sources, and timings are what those files hold.
- A hook path that fails closed: a fetch that breaks, or a session that stalls, because the
  classifier is unreachable, slow, or answers badly. Screening is meant to fail open.
- A banner the screened page can suppress, alter, or escape, so an injection reaches a model
  without a mark.
- A way to make the plugin act on instruction-like text found inside a screened page. The page is
  data under all circumstances.

## Out of scope

- The classifier's accuracy. A false negative or a false positive is a model question, and it
  belongs with TypeSafe.
- The page that served the hostile text, and whoever hosts it.
- What a model does after reading a banner. See the warning above.
- Vulnerabilities in Hermes itself, or in TypeSafe's service.

## Reporting

Use GitHub's private advisory form. Open the repository's **Security** tab and choose **Report a
vulnerability**. The report is visible to the maintainer alone, and the advisory stays private
until a fix ships.

If that form is not offered to you, open an issue saying only that you have a security report and
want a private channel. Leave the details out of the issue, and the maintainer will open an
advisory to continue in.

Never put a key, a page's contents, or the text of an injection payload in a public issue.

This is a single-maintainer project with no support contract. Reports are read and answered on a
best-effort basis. There is no response-time promise, because there is nobody to promise it on
behalf of.

## Versions

Version 1.0.0 is the only release. Fixes land on `main`, and the project carries no long-lived
release branches, so a fix is a commit rather than a backport.
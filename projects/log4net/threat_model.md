# Threat model: Apache log4net

This is a self-contained digest of the Apache Logging Services threat model, which governs log4net,
Log4j and Log4cxx alike. The authoritative versions are online (the scanner cannot reach them):

- https://raw.githubusercontent.com/apache/logging-site/refs/heads/main/src/site/antora/modules/ROOT/pages/_threat-model-common.adoc
- https://raw.githubusercontent.com/apache/logging-site/refs/heads/main/src/site/antora/modules/ROOT/pages/security/faq.adoc (frequently reported non-issues)
- https://logging.apache.org/cyclonedx/vdr.xml (previously disclosed vulnerabilities)

`AGENTS.md` at the repository root says the same for interactive research agents.

## What this project does and where untrusted input enters

log4net is an in-process logging library for .NET (`net462`, `netstandard2.0`). An application calls
`ILog.Info(...)` and friends; log4net formats the event with a layout and hands it to appenders
(files, console, syslog, UDP, SMTP, ADO.NET, event log, ...).

Every input is classified by who controls it:

- **Configuration is operator-supplied and trusted.** XML configuration files, configuration URIs,
  environment variables and app settings, including the type names, members and converters that
  configuration names, and the paths and destinations of appenders. A finding that requires the
  attacker to control configuration or a watched configuration file is out of scope.
- **Structural identifiers are developer-supplied and trusted.** Logger names, levels, the format
  string of `InfoFormat(...)`-style calls, and structural fields such as the syslog identity. Here
  log4net may *reject* (report) a malformed value instead of altering it.
- **Content is untrusted.** The log message, the string form of log parameters and exception
  messages, and the *values* of the thread and logical-thread context properties. The in-scope
  adversary controls exactly these and nothing else, and may submit arbitrary characters (CR, LF,
  NUL, malformed surrogates, control characters), very long values, and text that looks like
  pattern or format syntax. Content **must never be rejected**, since rejection turns a malicious
  value into a denial of service; it must be escaped where the output format requires it.

## Components that matter most / least

Matters most:

- **Structured output** must stay well-formed whatever the content: `XmlLayout`,
  `XmlLayoutSchemaLog4j`, and the RFC 5424/3164 framing built by `RemoteSyslogAppender` and
  `LocalSyslogAppender`. A content character that breaks the structure of the document log4net
  itself emits is a defect we own (log injection, CWE-117).
- `log4net.Appender.Internal.ContentEscape` and `RemoteSyslogAppender.AppendMessage`: the shared
  escapes are `\0` for NUL, `\r` and `\n`, and `\uXXXX` for anything else. A sink that cannot carry a
  character escapes it visibly; it never drops the character, the rest of the record, or the event.
- Anything where untrusted content reaches pattern converters, format expansion, or the network
  appenders (`UdpAppender`, `RemoteSyslogAppender`, `TelnetAppender`, the SMTP appenders in
  `log4net.Ext.Mail`).
- `TelnetAppender` is the only inbound network surface: it listens and streams events to whoever
  connects. Its listening address and port are configuration (trusted), but its handling of
  connections is in scope.
- Robustness: an appender must never let an exception escape to the logging caller, and must not
  hang, crash the process or leak resources because of content.

Less important or out of scope:

- `src/log4net.Tests`, `src/log4net.Tests.Aot`, `src/log4net.Ext.Mail.Tests`, `src/integration-testing`,
  `examples/`, `scripts/`, the site under `src/site`: tooling and tests, not shipped code.
- `PatternLayout` and other unstructured layouts make **no** injection guarantee: CR/LF in the output
  of a plain-text layout is by design (FAQ, CWE-93).

## How to exercise it

- NUnit 4 tests: `dotnet test src/log4net.Tests/log4net.Tests.csproj --no-build --filter <Name>`
  (the image is built and restored, so this runs offline). Use the constraint model,
  `Assert.That(actual, Is.EqualTo(expected))`.
- `src/log4net.Tests/Layout/XmlLayoutTest.cs` and `src/log4net.Tests/Appender/RemoteSyslogAppenderTest.cs`
  show how to drive a layout or appender in memory; `MemoryAppender` and `StringAppender` capture
  output without touching the file system.
- A good reproducer is a single NUnit test that logs crafted content and asserts on the formatted
  output.

## How you rate severity

Name the adversary first, then check that capability against the model above. If it needs a
capability the model does not grant, it is not a vulnerability: call it a correctness bug, a
reliability defect or hardening, and say so. That is more useful to us than a severity.

- **Critical**: code execution, or reading/writing arbitrary files, driven by untrusted content alone.
- **High**: untrusted content that breaks the structure of XML or RFC 5424 output, so that it forges or
  hides records for a parser that consumes the document as log4net emitted it; or that crashes the
  host process (an unhandled exception on a background thread, a stack overflow).
- **Medium**: denial of service from content within normal size limits (unbounded memory, CPU, or a
  hang of the logging call), or an event or part of a record silently lost because of its content.
- **Low**: resource leaks, missing escapes with no demonstrated parser impact, defense in depth.

Only claim impact you can demonstrate with the reproducer.

## Anything to leave alone

These are deliberate and are not vulnerabilities:

- Anything that requires control of configuration: type or assembly loading named in XML, file paths
  and path traversal in appender file names, the `ConfigureAndWatch` file, connection strings,
  configuration fetched from a URI, environment variables and app settings.
- Format strings: `ILog.InfoFormat(untrusted, ...)` is application misuse (`SystemStringFormat`).
- Untrusted data placed in logger names, levels or other structural identifiers by the application.
- Code running in the same process, including custom appenders, layouts, converters and plugins.
- A logged object whose `ToString()` throws, recurses or never terminates.
- A malicious appender destination: a hostile SMTP server, database, syslog receiver or file share.
- An attacker with write access to a log directory or file, including planting symbolic links there.
- **Active sinks**: ANSI escape sequences reaching a terminal (`AnsiColorTerminalAppender`,
  `ConsoleAppender`), spreadsheet formulas, shell metacharacters. log4net emits correct plain text;
  re-interpretation downstream belongs to the operator.
- CR/LF in `PatternLayout` output (FAQ, CWE-93), and CR/LF in the syslog `MSG` body where the RFCs
  leave escaping to the transport binding.
- Sensitive data in logs: log masking is out of scope, and access to log files is a deployer matter.
- Timing and other side channels.
- Deserialization: log4net never deserializes data. Types that still carry `[Serializable]` for
  backward compatibility are not a vulnerability; deserializing an untrusted stream is the caller's
  problem, and no allowlist of `log4net` types makes it safe.
- Unencrypted transports chosen in configuration (plain UDP, SMTP without TLS, plain-text Telnet).

## How reports and patches should look

One issue per report: affected component, the adversary and the content they control, the observed
output, a minimal NUnit 4 test that fails before the fix, and a proposed patch. The code base is C#
with nullability enabled and warnings as errors, 2-space indent, explicit types rather than `var`,
and `Log4NetAssert` for argument validation; keep the patch in that style. Prefer escaping in
`ContentEscape` over a new escape inside one appender. If no fix can be proposed, the finding is
probably not a vulnerability in log4net.

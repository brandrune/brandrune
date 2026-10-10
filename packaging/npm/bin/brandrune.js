#!/usr/bin/env node
// Brandrune runs inside Claude Code, not from npm. This prints how to install it.
"use strict";
process.stdout.write([
  "Brandrune is a Claude Code skill. Install it from inside Claude Code:",
  "",
  "  /plugin marketplace add brandrune/brandrune",
  "  /plugin install brandrune@brandrune",
  "",
  "Then ask: \"Name my app. It's a ...\"",
  "More: https://brandrune.com",
  ""
].join("\n"));

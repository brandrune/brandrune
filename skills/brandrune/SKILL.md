---
name: brandrune
description: Name a product, app, or project and find names whose .com (or other domain) is actually unregistered, checked live against the registries. Plain-text names, real filters (length, extension, required word, style, available only), and a clean filterable page. Use when someone says "name this", "what should I call", "I need a name for", "brainstorm names", "find an available domain", "is X.com taken", "Namelix", "brandrune", or "weavenames" (its old name).
---

# Brandrune

You come up with the names. The bundled script checks them. The script is the
only source allowed to say a domain is open, and it only says so when the
registry for that extension answered "no such domain" in this session.

Script: `scripts/brandrune.py` in this skill's directory (the base directory is
shown when the skill loads). It needs Python 3.9 or newer and nothing else.
Below, `BR` means `python3 <skill dir>/scripts/brandrune.py`.

## The rules that make this reliable

1. **Never call a domain available unless the script printed `open` for it in
   this session.** Not from memory, not because it sounds obscure, not from a web
   search. If you have not checked it, say "not checked".
2. **`unknown` is not available.** It means the script got no usable registry
   answer: no reply after retries, a redirect, a reply it could not read, a
   registry that failed the sanity check or has a bad certificate, or an
   extension it does not support. Say so, and re-check with `BR verify <domain>`
   if the name matters.
3. **`open*` means unregistered, price not verified.** The script cannot rule
   out premium or registry-reserved names, which also look unregistered, unless
   a Vercel token confirmed the standard price for that row. Say "unregistered
   (price not verified)", never "free" and never the price as if it were
   confirmed. A plain `open $11` with no star is the only verified price.
4. **Re-verify your final picks** with `BR verify` right before you recommend
   them. It takes a second and the answer is fresh.
5. **Report what the script reported.** If a filter leaves 6 names, show 6. Do not
   pad the list with names you did not check.

## Process

### 1. Get the description

You need one or two sentences about what is being named and who it is for. If
the request already has that, start. If not, ask one question and go. Also pick
up any constraints they stated: length, required word, extensions, style,
"must have the .com". Default extension is **.com only**; add others only when
asked or when the project clearly calls for one (.ai for an AI product, .dev or
.io for developer tools).

### 2. Write the candidates

Write about 150 names to a file, one per line, each followed by one style word:

```
strumdaily compound
fretwise compound
chordial blend
lumora invented
```

Styles (use these exact words so the style filter works): `real-word`,
`compound` (two whole words), `blend` (two words overlapped), `phrase` (three or
more short words, like getaroundtown), `respelled` (an altered spelling, like
lyft), `prefixed` (get-, try-, use-, my-, go-), `suffixed` (-ly, -ify, -hq,
-hub, -app), `invented` (a made-up word), `foreign` (a word from another
language).

What makes a good batch:

- **A person can say it after reading it once, and spell it after hearing it
  once.** This is the most common failure. Strings like "klaxum" or "zaxel" are
  not names.
- **Spread the styles, by count.** Unless they asked for one style, aim for
  roughly: 40 compound, 25 blend, 20 phrase, 20 invented, 15 respelled,
  10 real-word, 10 prefixed, 10 foreign. Single real words are almost always
  taken as .com, which is why they get the fewest. Count your lines by style
  before you check; a batch that is nearly all one style gives the filters
  nothing to work with.
- **No suffix farming.** Do not use any ending or root more than three times in
  a batch. A batch that reads Proxel, Vexel, Nexel, Zaxel is broken.
- **Not a literal description.** "MetronomeTrackerApp" names the feature, not
  the product.
- **Lowercase letters and digits only, 3 to 20 characters,** unless they asked
  for something else. Hyphens are allowed by registries but people forget them;
  avoid them unless asked.
- **Match their constraints exactly.** If they said 8 letters or fewer, every
  line is 8 or fewer.

Save it in a scratch folder, for example `/tmp/brandrune-<slug>/names.txt`, and
write their description, as they gave it, to `/tmp/brandrune-<slug>/about.txt`.
Pass the description by file, never inside quotes on the command line, so
nothing in it gets run by the shell.

### 3. Check them

```bash
BR check /tmp/brandrune-<slug>/names.txt \
  --description-file /tmp/brandrune-<slug>/about.txt \
  --out /tmp/brandrune-<slug>/results.json \
  --html /tmp/brandrune-<slug>/names.html
```

Add `--tlds com,ai` (and so on) for more extensions; the first one listed is the
main one and sorts the results. Two-part extensions such as .co.uk are not
supported. A .com-only run of 150 names takes a few seconds. .app and .dev are
slower, about one name per second, because Google's registry limits request
rates.

### 4. Go another round if the pool is thin

If fewer than about 15 names you would actually recommend came back `open` on
the main extension, write another batch. Lean toward the styles and patterns
that came back open, and drop the ones that were all taken. Append it to the
same file and run the same `check` command again. It re-checks every name, so
every answer is from this run.

Three rounds is usually enough. If it is still thin, say so plainly.

### 5. Show the results

Give a short, plain-text answer:

- **Your pick** and one line on why.
- **Four or five strong alternatives.**
- **The domain status for each, in the script's words:** open (with the price
  if it showed one), open*, premium with its price, parked (owned and probably
  for sale by a domain reseller), taken.
- **Where the full list is:** the HTML page path. It is a clean light page with
  every name as plain text, plus filters for contains-word, length, style, and
  which extensions must be open. Offer to open it (`open` on macOS,
  `xdg-open` on Linux).

Do not paste the whole table unless they ask.

### 6. Filter on request

They can filter in plain words. Map it to `show`, which re-filters the saved
results without querying again:

Use the full folder path from step 3 in every command; a shell variable set in
one command is gone by the next.

| They say | Run |
|---|---|
| "only ones with the .com" | `BR show /tmp/brandrune-<slug>/results.json --available-only` |
| "8 letters or fewer" | `BR show /tmp/brandrune-<slug>/results.json --max-len 8` |
| "has to have 'strum' in it" | `BR show /tmp/brandrune-<slug>/results.json --include strum` |
| "no 'ly' endings" | `BR show /tmp/brandrune-<slug>/results.json --exclude ly` |
| "just compounds and blends" | `BR show /tmp/brandrune-<slug>/results.json --style compound,blend` |
| ".com and .ai both open" | `BR show /tmp/brandrune-<slug>/results.json --open com,ai` |
| "anything with an open domain" | `BR show /tmp/brandrune-<slug>/results.json --any-open` |

Filters combine. Add `--limit 20` to cap the rows, and `--html` to
redraw the page (`--html /tmp/brandrune-<slug>/names.html`). Results older than a day come with a warning; re-run `check`
before you trust an open answer that old.

### 7. Before they commit to a name

For the one or two names they lean toward:

- `BR verify <name>.com` (plus any other extension they want) for a fresh answer.
- One web search for `"<name>" <their industry>`. A live business in the same
  field using the name is a problem even if the .com is open. Report what you
  found; this is a judgment, not a registry answer, so label it as one.
- For a trademark, point them to the USPTO search at
  https://tmsearch.uspto.gov and say you have not cleared it. This skill does
  not do trademark clearance.

They register the domain themselves. This skill never buys anything.

## Checking a single name

"Is fretwise.com taken?" needs no generation:

```bash
BR verify fretwise.com fretwise.ai
```

## What each status means

| Status | What the script saw |
|---|---|
| `open $11` | The registry has no record, and the registrar confirmed it sells at the standard price shown. Needs a Vercel token. |
| `open*` | The registry has no record. Price not verified for this row, so premium or reserved is still possible. A price after the star is the registrar's quote, not a confirmed standard price. |
| `premium` | No registry record, but the registrar prices it well above standard. The price is shown. |
| `reserved` | No registry record, but the registrar will not sell it. |
| `taken` | The registry returned a registration. |
| `parked` | Taken, and its nameservers belong to a parking or domain-sale service. Often buyable from a reseller, at a markup. |
| `expiring` | Taken but in redemption or pending delete. It may drop back to open. |
| `unknown` | No usable registry answer. Never counted as open. |

Where the answers come from: .com and .net from Verisign, and most other
extensions from their registry's RDAP server, located through IANA's bootstrap
file. .io, .co, .sh, .me, .so and .gg have no RDAP server, so their registry's
WHOIS is used instead, and an unrecognized WHOIS reply is reported as `unknown`.
Redirects are never followed, a "not found" only counts when it comes back as a
real RDAP reply, and before any name on an extension is called open, the script
confirms that registry reports nic.<extension> or google.<extension> as
registered. Extensions with no RDAP server and no WHOIS entry in the script
(for example .us, .de, .eu, .ch, .es, .it, .nz), two-part ones like .co.uk,
and .fi (its "not found" is an HTML page) always come back `unknown`. Run
`BR verify <name>.<ext>` first if you are unsure an extension works.
Every answer is stored in `results.json` with the URL or server that gave it and
the time.

## Optional setup

None of this is required. Each item makes one part sharper.

- **`VERCEL_TOKEN`**: turns `open*` into a priced `open`, and catches premium
  and reserved names. Any free Vercel account works. Create a token at
  https://vercel.com/account/tokens and export it. If it is a team token, also
  export `VERCEL_TEAM_ID`. A token that does not work is reported once and the
  run continues unpriced.

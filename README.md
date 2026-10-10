# Brandrune

**Names you can read. Domains that are really open.**

A free naming skill for Claude Code and Codex. Describe what you build in a
sentence. Your coding agent writes about 150 names, and a small script asks the
domain registries about every one. You get plain-text names, filters you actually control, and a
clean page to browse them. Site: https://brandrune.com

It exists because the usual name generators have two problems: the names come
back styled as logos, so they are hard to read, and the page is noisy. There is
a third problem in most of them: "available" is a guess. Here it is not. A domain is only called open when the registry for that
extension says it has no record of it, in the same run.

Free, forever. No account, no API key, no paid tier.

## Install

### Claude Code

In Claude Code:

```
/plugin marketplace add brandrune/brandrune
/plugin install brandrune@brandrune
```

On Claude Code 2.1.275 or later this also works in one step:

```
/plugin install brandrune --marketplace brandrune/brandrune
```

Or copy the skill folder by hand:

```bash
git clone https://github.com/brandrune/brandrune
cp -r brandrune/skills/brandrune ~/.claude/skills/
```

It needs Python 3.9 or newer, which macOS and most Linux systems already have.
There is nothing to pip install and no API key to set.

### Codex

Ask Codex to install the skill:

```text
$skill-installer install https://github.com/brandrune/brandrune/tree/main/skills/brandrune
```

Or copy the same skill folder by hand into Codex's user skill directory:

```bash
git clone https://github.com/brandrune/brandrune
mkdir -p ~/.agents/skills
cp -r brandrune/skills/brandrune ~/.agents/skills/
```

For one repository only, copy it into that repository's `.agents/skills/`
instead. Choose one location to avoid duplicate skills. Codex detects new
skills automatically; restart it if Brandrune does not appear.

The same Python requirement applies. `pip install brandrune` and
`npx brandrune` print installation instructions; they do not install the skill.

See the [official Codex skills guide](https://learn.chatgpt.com/docs/build-skills).

### Coming from weavenames

Brandrune was called weavenames until version 0.3.0. An existing
`weavenames@weavenames` install keeps working: the marketplace still lists
`weavenames` as an alias, so the next marketplace update brings you Brandrune
under the old name. The skill also still answers when you ask for "weavenames".

To move to the new name for good, once:

```
/plugin uninstall weavenames@weavenames
/plugin marketplace remove weavenames
/plugin marketplace add brandrune/brandrune
/plugin install brandrune@brandrune
```

Keep only one of the two installed, or the skill loads twice.

## Use

In Codex, invoke it explicitly:

```text
$brandrune Name my app. It's a practice tracker for adults learning guitar.
```

Or let Claude Code or Codex select the skill from a matching request.
Ask in plain words:

> Name my app. It's a practice tracker for adults learning guitar, with a
> streak and a metronome built in.

> I need a name for a CLI that cleans up dotfiles. Short, and the .com has to be
> open.

> Is lumenfret.com taken?

Your coding agent writes about 150 candidates in a mix of styles, the bundled
script checks every one, and you get a short recommendation plus a filterable page with the
full list. Then filter by talking:

> Only 8 letters or less. Has to have "strum" in it. Just compounds.

## What "open" means

| Status | Meaning |
|---|---|
| open $11 | The registry has no record, and the registrar confirmed it sells at the standard price shown. Needs a Vercel token. |
| open* | The registry has no record. Price not verified, so a premium or reserved name is still possible. |
| premium | No registry record, but it is priced well above standard. |
| reserved | No registry record, but no registrar will sell it. |
| taken | Registered. |
| parked | Registered, and parked at a domain-sale service. Often buyable from a reseller, at a markup. |
| expiring | Registered, but in redemption or pending delete. |
| unknown | No usable registry answer: no reply after retries, a redirect, an unreadable reply, or an unsupported extension. Never counted as open. |

Answers come straight from the registries: .com and .net from Verisign, most
other extensions from their registry's RDAP server (found through IANA's
bootstrap list), and .io, .co, .sh, .me, .so and .gg from their registry's
WHOIS, since those have no RDAP server. Redirects are never followed, a "not
found" only counts when it is a real RDAP reply, and each registry must first
report nic.<extension> or google.<extension> as registered before any name on
it is called open. Extensions with neither an RDAP server nor a WHOIS entry in
the script (for example .us, .de, .eu, .ch, .es, .it, .nz), two-part ones such
as .co.uk, and .fi always come back unknown.
Every answer is saved with the server that gave it and the time.

## What leaves your machine

The candidate names go to the domain registries that answer for them, and to
Vercel's domain API only if you set a token. Your description stays in your own
Claude Code or Codex session. Brandrune has no server and collects nothing.

## Optional setup

- **`VERCEL_TOKEN`** turns `open*` into a priced `open` and catches premium and
  reserved names, which a registry lookup alone cannot see. Any free Vercel
  account works: create a token at https://vercel.com/account/tokens. Add
  `VERCEL_TEAM_ID` if it is a team token.

## The script on its own

The checker works without a coding agent too:

```bash
S=skills/brandrune/scripts/brandrune.py
python3 $S verify lumenfret.com lumenfret.ai
python3 $S check names.txt --tlds com,ai --out results.json --html names.html
python3 $S show results.json --available-only --max-len 9 --include strum
```

`names.txt` is one name per line, optionally followed by a style word.
`python3 $S check --help` lists every filter.

## What it does not do

- Buy domains. You register the one you pick, wherever you like.
- Clear trademarks. It points you to the USPTO search; that check is yours.
- Make logos.

## Development

```bash
python3 -m unittest discover -s tests
```

The tests are offline and fake every registry answer. Earlier versions (a
Python package with its own model calls and ranking, published as weavenames)
live in the git history, up to commit `cffa5dd`.

## License

MIT

# Packaging

Pointer packages for the registries. The skill itself installs through the
Claude Code marketplace in the repo root; none of these contain the checker.

| dir | registry | package | publish |
|---|---|---|---|
| `npm/` | npm | `brandrune` | `cd npm && npm publish` |
| `pypi/` | PyPI | `brandrune` | `cd pypi && python3 -m build && twine upload dist/*` |
| `pypi-weavenames/` | PyPI | `weavenames` 0.0.2 | same, from `pypi-weavenames/` |

After publishing, point the old npm name at the new one:

```
npm deprecate weavenames "Renamed to brandrune. Install in Claude Code: /plugin marketplace add brandrune/brandrune"
```

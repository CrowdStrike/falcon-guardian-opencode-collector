# falcon-guardian-opencode-collector

Falcon Guardian collector for OpenCode.

## Setup

Set the following environment variables:

- `FALCON_GUARDIAN_OPENCODE_TOKEN`: Falcon Guardian API token.
- `FALCON_GUARDIAN_OPENCODE_BASE_URL`: Falcon Guardian API base URL.

If either is unset or empty, the collector falls back to the shared
`CS_AIDR_TOKEN` and `CS_AIDR_BASE_URL` variables.

Then restart the OpenCode background server:

```
opencode service restart
```

## Usage

Load the plugin in `opencode.json(c)`:

```jsonc
{
  "plugins": [
    {
      "package": "@crowdstrike/falcon-guardian-opencode-collector",
      "options": { "failureMode": "closed" },
    },
  ],
}
```

## Configuration

| Option | Env | Default |
|---|---|---|
| | `FALCON_GUARDIAN_OPENCODE_TOKEN`, then `CS_AIDR_TOKEN` | required |
| `baseURL` | `FALCON_GUARDIAN_OPENCODE_BASE_URL`, then `CS_AIDR_BASE_URL` | `https://api.crowdstrike.com/aidr/aiguard` |
| `timeout` (seconds) | | `30` |
| `failureMode` (`open` or `closed`) | | `closed` |

## Develop

```sh
pnpm install
pnpm test
pnpm lint && pnpm typecheck
pnpm build
```

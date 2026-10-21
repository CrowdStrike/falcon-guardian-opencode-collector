# falcon-guardian-opencode-collector

Falcon Guardian collector for OpenCode.

## Setup

Set the following environment variables:

- `CS_AIDR_TOKEN`: Falcon Guardian API token.
- `CS_AIDR_BASE_URL`: Falcon Guardian API base URL.

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
| `token` | `CS_AIDR_TOKEN` | required |
| `baseURL` | `CS_AIDR_BASE_URL` | `https://api.crowdstrike.com/aidr/aiguard` |
| `timeout` (seconds) | | `30` |
| `failureMode` (`open` or `closed`) | | `closed` |

## Develop

```sh
pnpm install
pnpm test
pnpm lint && pnpm typecheck
pnpm build
```

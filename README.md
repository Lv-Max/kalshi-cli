# kalshi-cli

A tiny, **zero-dependency** Go CLI for the [Kalshi](https://kalshi.com) `trade-api/v2`.
Query markets / order books and place orders directly against Kalshi's official API.
Every request is signed locally with your RSA private key (RSA-PSS / SHA-256) — no
third-party service ever sees your key. Compiles to a single static binary with no
runtime dependencies.

## Build

Requires Go 1.21+ (standard library only — no external modules).

```sh
go build -o kalshi .
```

Cross-compile for another OS/arch — the binary is statically linked, just copy it over:

```sh
GOOS=linux   GOARCH=amd64 go build -o kalshi .       # Linux server
GOOS=darwin  GOARCH=arm64 go build -o kalshi .       # Apple Silicon
GOOS=windows GOARCH=amd64 go build -o kalshi.exe .   # Windows
```

## Configure

Generate credentials at kalshi.com → Profile → **API Keys → Create New API Key**
(the RSA private key is shown **once** — save it). Then:

```sh
cp kalshi.config.example.json kalshi.config.json
# put your RSA private key in a file, e.g. kalshi.pem
```

`kalshi.config.json`:

```json
{
  "keyId": "your-api-key-id",
  "pemPath": "kalshi.pem",
  "defaultEnv": "demo"
}
```

- `keyId` — your Kalshi API Key ID
- `pemPath` — path to the RSA private key PEM (PKCS#1 `BEGIN RSA PRIVATE KEY` or PKCS#8 `BEGIN PRIVATE KEY`)
- `defaultEnv` — `demo` or `prod`

The CLI looks for `kalshi.config.json` in the current directory, then next to the
binary; override with `--config <path>` or `$KALSHI_CONFIG`.

**Never commit `kalshi.config.json` or your `.pem`** — both are gitignored.
Production and demo are **separate accounts**: demo needs its own key from demo.kalshi.co.

## Usage

Read commands (safe, no writes):

```sh
kalshi status                                   # exchange status (no auth needed)
kalshi balance --prod                           # account balance
kalshi markets --grep "fed" --status open       # list/filter markets
kalshi book  <ticker> --depth 10                # order book
kalshi quote <ticker>                           # last price / bid / ask / volume
kalshi orders --status resting                  # your open orders
kalshi positions                                # your positions
```

Write commands (gated — see below):

```sh
kalshi buy  <ticker> <count> [--yes|--no] [--price <cents>] [--type limit|market]
kalshi sell <ticker> <count> [--yes|--no] [--price <cents>] [--type limit|market]
kalshi cancel <order_id>
```

Global flags: `--prod` `--demo` `--confirm` `--raw` `--config <path>`
(`--raw` prints the raw JSON response of any command).

### Safety gates

- **Defaults to demo.** Add `--prod` to hit production (real money).
- **Write commands are dry-run by default** — they print the exact request and send
  nothing. Add `--confirm` to actually send.
- A live order therefore requires **both** `--prod --confirm`.

```sh
# preview only (prints the order body, sends nothing):
kalshi buy KXLOLMAP-26JUN282300KCT1-3-T1 1 --yes --price 78 --prod
# actually places a real order:
kalshi buy KXLOLMAP-26JUN282300KCT1-3-T1 1 --yes --price 78 --prod --confirm
```

## Notes

- Prices are in cents (1–99). `count` is whole contracts.
- Base URLs: production `https://api.elections.kalshi.com/trade-api/v2`,
  demo `https://external-api.demo.kalshi.co/trade-api/v2`.
- Flags may appear before or after positional arguments.
- Auth scheme: sign `timestamp_ms + METHOD + path` (no query string) with RSA-PSS
  (SHA-256, salt length = digest); send `KALSHI-ACCESS-KEY` / `-TIMESTAMP` / `-SIGNATURE`.

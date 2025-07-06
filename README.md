# Riot Take-Home Technical Challenge

Original specifications can be found here [SPECIFICATIONS.md](SPECIFICATIONS.md)

## Quick Start

```bash
# Install dependencies
yarn

# Set up environment variables
cp .env.example .env
# Edit .env and set your HMAC_SECRET value

# Run tests
yarn test

# Start development server
yarn dev

# Test the API
curl -X POST http://localhost:3000/encrypt -H "Content-Type: application/json" -d '{"name":"John Doe","age":30}'
```

## Environment Variables

The application requires the following environment variables:

- `HMAC_SECRET`: Secret key used for HMAC signing and verification (required)
- `HOST`: Host IP for the server (optional, defaults to 0.0.0.0)
- `PORT`: Port number for the server (optional, defaults to 3000)

Copy `.env.example` to `.env` and set your values:

```bash
cp .env.example .env
```

The application will not start if `HMAC_SECRET` is not defined.
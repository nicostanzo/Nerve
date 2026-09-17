# Nerve WAF

A high-performance, edge-native Web Application Firewall (WAF) designed specifically for Vercel Edge Middleware.

## Features
- **Zero-Latency Rate Limiting:** Local sliding window rate limiter optimized for Serverless/Edge environments (no external dependencies required).
- **Anomaly Scoring Engine:** OWASP CRS-style scoring system for complex payload evaluation.
- **Deep Canonicalization:** Decodes and normalizes UTF-7, Hex, Unicode Escapes, and safely strips combining diacritical marks (NFD) to prevent evasion.
- **Recon Bot Shield:** Blocks known automated vulnerability scanners.
- **Header Inspection:** Spoofed IP detection, hostile routing header blocks, and X-Forwarded-For validation.
- **Payload Inspection:** SQLi, XSS, Path Traversal, SSRF, and Prototype Pollution prevention up to 32KB payload size (fail-closed on oversize).

## Installation

1. Copy the middleware.js file into the root of your Vercel project (or src/ directory if using Next.js src folder structure).
2. Configure your desired variables in the WAF_CONFIG object inside the file.
3. Deploy to Vercel.

## Configuration

Adjust the WAF_CONFIG settings at the top of the file:
- mode: 'ENFORCE' (blocks threats) or 'OBSERVE' (logs only).
- ateLimitMax: Maximum requests per minute per client fingerprint (default is 60).
- ateLimitWindowMs: Sliding window time frame in milliseconds (default is 60000).

## Telemetry
The WAF outputs telemetry logs to the standard Edge Function console. Each block event includes an Event ID, action, HTTP status code, and reason.



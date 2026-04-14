# Reference: subdomain-takeover

## Fingerprint Database

Service fingerprints used to detect unclaimed resources via HTTP response body matching.

| Service key | Fingerprint string |
|-------------|-------------------|
| `github-pages` | `There isn't a GitHub Pages site here` |
| `s3` | `NoSuchBucket` |
| `heroku` | `No such app` |
| `netlify` | `Not Found - Request ID` |
| `azure-trafficmanager` | `404 Not Found` |
| `azure-blob` | `BlobNotFound` |
| `azure-cloudapp` | `404 Web Site not found` |
| `shopify` | `Sorry, this shop is currently unavailable` |
| `fastly` | `Fastly error: unknown domain` |
| `ghost` | `Failed to resolve DNS for` |
| `pantheon` | `The gods are wise, but do not know of the site which you seek` |
| `tumblr` | `There's nothing here` |
| `wordpress-com` | `Do you want to register` |
| `cargo-collective` | `404 Not Found` |
| `surge-sh` | `project not found` |
| `bitbucket` | `Repository not found` |
| `zendesk` | `Help Center Closed` |
| `readme-io` | `Project doesnt exist` |
| `statuspage` | `Better Uptime` |

## Service-Specific Claim Verification

For each candidate identified during fingerprint scanning, confirm the resource is truly unclaimed before reporting.

| Service | CNAME pattern | Claim check |
|---------|--------------|-------------|
| GitHub Pages | `*.github.io` | Try creating `github.com/<username>/<cname-prefix>` repo with `gh-pages` branch |
| AWS S3 | `*.s3.amazonaws.com` or `s3-*.amazonaws.com` | Try `aws s3 mb s3://<bucket-name>` in the appropriate region |
| Heroku | `*.herokuapp.com` | Try `heroku create <app-name>` |
| Netlify | `*.netlify.app` | Try creating a Netlify site with the matching custom domain |
| Azure Traffic Manager | `*.trafficmanager.net` | Try creating an Azure Traffic Manager profile with the name |
| Shopify | `*.myshopify.com` (via custom domain) | Check if the Shopify store name is available |
| Fastly | Any domain with Fastly 422 | Check if the CNAME hostname is registered as a Fastly service domain |

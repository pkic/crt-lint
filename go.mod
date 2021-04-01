module github.com/pkic/testlint

go 1.16

require (
	github.com/cloudflare/cfssl v1.5.0
	github.com/lib/pq v1.10.0
	github.com/zmap/zcrypto v0.0.0-20210329121109-8d3578e757f2
	github.com/zmap/zlint/v3 v3.1.0
)

// Replace the pkic version on the right with `state-province` (the branch name) and run `go mod tidy` to get te latest version
replace github.com/zmap/zlint/v3 v3.1.0 => github.com/pkic/zlint/v3 v3.0.1-0.20210401100233-5d6a19a479b0

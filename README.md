A command line utility for running a specific ZLint linter against the [crt.sh](https://crt.sh) database of certificates logged to certificate transparency.

## Installation

To install crt-lint, you will need to have Go installed on your system. Once you have Go installed, you can run the following command to install crt-lint:

go get github.com/pkic/crt-lint

## Usage

To run crt-lint, you will need to specify the linter that you want to use and the domain that you want to check. For example, to run the CertificatePoliciesLinter on the domain example.com, you would run the following command:

```shell
usage: `crt-lint [flags]`
  -batch int
        Number of certificates to ask for per query (default 1000)
  -lint string
        Lint name (required)
  -offset int
        Last crt.sh ID processed
  -out string
        Output filename (default "result.csv")
  -workers int
        Number of concurrent worker (default 10)
```

## Testing locally

To test new or updates to your lints you can simply use a Go workspace pointing to the local versions.

Clone this repository and the ZLint repository if you haven't done so yet:

```shell
git clone git@github.com:pkic/crt-lint.git
git clone git@github.com:zmap/zlint.git
```

Configure your Go workspace so that it's aware of the local repository and ignores the remote that doesn't hold the changes:

```shell
go work init
go work use crt-lint zlint
```

Now you can test the local version of the lint with the following command:

```shell
go run ./crt-lint -lint e_name_of_the_lint
```

## Contributing

If you would like to contribute to crt-lint, please fork the repository and submit a pull request. We welcome any and all contributions!
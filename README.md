# swcli 🪛

## Table of contents

- [Usage](#usage)

<a id="usage"></a>

## Usage

### Get an AWS CodeArtifact token


```shell
# Providing access keys
export AWS_ACCESS_KEY_ID=xxxxx
export AWS_SECRET_ACCESS_KEY=yyyyy
export AWS_SESSION_TOKEN=zzzzz

swcli codeartifact get-authorization-token --domain=my-domain --domain-owner=my-domain-owner --region=some-aws-region

# When already logged-in via `aws sso login --profile my-profile`
export AWS_PROFILE=my-profile

swcli codeartifact get-authorization-token --domain=my-domain --domain-owner=my-domain-owner --region=some-aws-region
```

### Install

Pre-built binaries are attached to each [GitHub release](https://github.com/ZeroGachis/swcli/releases).

Besides the immutable `swcli-X.Y.Z` releases, the mutable `swcli-X` and `swcli-X.Y` releases always contain the binaries of the latest matching version:

```shell
# Pin a full version
curl -L -O https://github.com/ZeroGachis/swcli/releases/download/swcli-0.1.4/swcli-linux-musl-x86_64

# Latest 0.1.x version
curl -L -O https://github.com/ZeroGachis/swcli/releases/download/swcli-0.1/swcli-linux-musl-x86_64

# Latest 0.x.y version
curl -L -O https://github.com/ZeroGachis/swcli/releases/download/swcli-0/swcli-linux-musl-x86_64
```

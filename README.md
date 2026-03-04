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

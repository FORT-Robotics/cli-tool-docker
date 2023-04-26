`fort_cli_cfg` is a Python-based command line utility which be used to configure
FORT's EPC (over IP via Ethernet/Wi-FI) or FRC (over USB) by exercising the CoAP
configuration interface for the specified device.

# Installation

## Normal

Install to the local environment (from the root directory)

```bash
pip install .
```

##  Poetry

From project root

```bash
poetry install
```

# Running

## Normal

```bash
# See latest command line options supported
fort_cli_cfg -h
```

## With Poetry

From project root

```bash
poetry run fort_cli_cfg <args>
```

## Configurations

Default EPC or FRC json config files loaded automatically with -e or -f options.
Use -j to specify an alternate json config file.

The **configs** folder contains alternate config files, such as **dev.json** for
the development web config endpoints.

# Code Quality Checks

The `fort_cli_cfg` tool has a BitBucket Pipeline which runs
[flake8](https://flake8.pycqa.org/en/latest/) and
[pre-commit](https://pre-commit.com/) hooks which check for PEP8 and basic
end-of-line and trailing white space checks respectively.

## flake8 - Manually Run

To manually run `flake8` on your local develop PC, run the following commands
from within the root directory of your clone of `fort-cli-cfg` git repo:

```bash
# Install flake8
pip install flake8

# Run flake8
flake8 . --extend-exclude=dist,build --show-source --statistics
```

## Run/Install Pre-Commit Hooks

Pre-Commit is a handy Python utility which installs Git hooks onto a local
checkout of the `fort-cli-cfg` Git repository.

The pre-commit hooks which are used are contained within the
`.pre-commit-config.yaml` file within this repository. For details on all the
hooks availabe, see https://pre-commit.com/hooks.html.

From the root directory of your clone of the `fort-cli-cfg` source, run the
following commands:

```bash
# Install Pre-Commit
pip install pre-commit

# Install Git Hooks
pre-commit install

# Manually run pre-commit hooks
pre-commit run --all-files
```

# Publishing

To publish a new version of `fort-cli-cfg` to JFrog, the following should be done:

1. Update `pyprojct.toml` with new version
2. Merge changes to master
3. Create tag of new version in Git Repository of the merge commit on master
   a. Tag must follow `vX.Y.Z` where `X.Y.Z` matches version in `pyproject.toml`

Upon creating the new tag, a Bitbucket Pipeline will be spawned which will
publish the artifact to JFrog.

## Manual Steps

Here are the commands that will publish the fort-cli-cfg to FORT's JFrog PyPI:

```
# Config the pypi URL to upload artifact to
poetry config repositories.fort  https://fortrobotics.jfrog.io/fortrobotics/api/pypi/pypi-local

# Test building and publishing (--dry-run)
poetry publish --build -r fort -u <jfrog-username> -p <jfrog-password> --dry-run

# Publish new version
poetry publish --build -r fort -u <jfrog-username> -p <jfrog-password>
```

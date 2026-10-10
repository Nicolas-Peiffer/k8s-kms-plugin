#!/usr/bin/env bash

# ENV
CURRENT_PATH="$(realpath "$0")"
CURRENT_DIR="$(dirname "${CURRENT_PATH}")"
PROJECT_DIR="$(dirname "${CURRENT_DIR}")"

# VARS
build_args=(go build)
dev_mode=false
debug_mode=false
branch_name=""

# FUNCTIONS

# validate_branch_name rejects anything that is not a plain git branch name.
#
# The value reaches `git switch` and a `go get` module query. Both now receive it as a single
# argument rather than as shell text, so this is no longer what stands between a branch name and
# command execution — removing `eval` is. It is kept because an argument beginning with "-" is
# still read as an option by either command, and because restricting the value to the refname
# subset this script needs is cheap.
function validate_branch_name(){
    local name="$1"
    if [[ ! "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
        echo "ERROR: invalid branch name '${name}'" >&2
        echo "       expected letters, digits, '.', '_', '/' or '-', starting with a letter or digit" >&2
        exit 1
    fi
    if [[ "${name}" == *..* ]]; then
        echo "ERROR: invalid branch name '${name}': '..' is not valid in a git refname" >&2
        exit 1
    fi
}

function help(){
    printf "[Overview]
build.sh --help
This script helps to build the k8s-kms-plugin, covering different development and debug options.

[Usage]
build.sh [opts:--dev|--debug]

[Arguments]

[Options]
--dev [branch_name]     Optional. If enabled, use the git branch name to pull the Crypto11 and Gose dependencies and build the k8s-kms-plugin with it.
--debug                 Optional. If enabled, use delve to build the k8s-kms-plugin for remote debug.

[Examples]
$ build.sh
  # build the k8s-kms-plugin

$ build.sh --dev my-feature-branch
  # switch to my-feature-branch and build the k8s-kms-plugin against the crypto11 and gose
  # revisions on the branch of that name
"
}

function init(){
    #echo "init vars and env here"
    if [ "${dev_mode}" = true ]; then
      if [ -z "${branch_name}" ]; then
        echo "ERROR: dev mode needs a branch name in arguments"
        help
        exit 1
      fi
      validate_branch_name "${branch_name}"
      echo "Dev mode enabled"
      echo "Build using branch ${branch_name}"
      # No eval: GOPROXY=direct is an ordinary command prefix, and the module queries are
      # single arguments. With eval, every shell metacharacter in a branch name was executed.
      if ! git switch "${branch_name}"; then
          echo "ERROR: cannot switch to branch '${branch_name}'" >&2
          exit 1
      fi
      for module in "github.com/eclipse-keypont/crypto11/v2" "github.com/eclipse-keypont/gose"; do
          if ! GOPROXY=direct go get -u "${module}@${branch_name}"; then
              echo "ERROR: cannot get ${module}@${branch_name}" >&2
              exit 1
          fi
      done
      go mod tidy
    fi

    if [ "${debug_mode}" = true ]; then
      echo "Debug mode enabled"
      # Quoted normally, not escaped: the array is expanded as arguments rather than passed
      # through eval, so "all=-N -l" survives as one word without the backslashes that the
      # eval form needed.
      build_args+=(-gcflags=all=-N\ -l)
      echo "${build_args[@]}"
    fi

    build_args+=(-o k8s-kms-plugin "${PROJECT_DIR}/cmd/k8s-kms-plugin/main.go")
}

# customize image
function start(){
#    build_cmd="go ${build_args[@]}"
    # build
    echo "build k8s-kms-plugin"
    # Expanded as an argument vector, not re-parsed as a shell command.
    "${build_args[@]}"

    echo "Done"
}

# PARSING
#if [ $# -eq 0 ]; then help; fi # if no arguments given to this script
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
    -h|--help|help)
        help
        exit 0
        ;;
    --dev)
        # `shift 2` with only "--dev" left shifts nothing and returns non-zero, which spun
        # this loop forever instead of reporting the missing value.
        if [ $# -lt 2 ]; then
            echo "ERROR: --dev requires a branch name" >&2
            help
            exit 1
        fi
        dev_mode=true
        branch_name="$2"
        shift 2
        ;;
    --debug)
        debug_mode=true
        shift
        ;;
    *) # unknown option
        # This called an undefined "format", so an unknown option printed
        # "command not found" and the script carried on regardless.
        echo "ERROR: unknown option '$1'" >&2
        help
        exit 1
        ;;
    esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

# MAIN
init
start

exit 0
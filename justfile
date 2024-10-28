alias i:= install
alias l:= lint
alias c:= coverage
alias cn:= clean
alias t:= test
alias f:= format
alias h:= set-hooks
alias d:= serve-docs
alias b:= build-docs

@help:
    just --list

@install:
    bash ./scripts/install

@lint:
    ./scripts/lint

@format:
    ./scripts/format

@test:
    ./scripts/test

@coverage:
    ./scripts/coverage

@clean:
    ./scripts/clean

@set-hooks:
    ./scripts/pre-commit
    ./scripts/pre-push

@serve-app:
    uvicorn app.app:app --reload --port=6969

@serve-docs:
    mkdocs serve

@build-docs:
    mkdocs build

@info:
  echo "Running on {{arch()}} machine".

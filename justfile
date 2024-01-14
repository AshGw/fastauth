@help:
    just --list

@install:
    chmod +x ./install
    ./install

@lint:
    ./scripts/lint


@format:
    ./scripts/format

@clean:
    ./scripts/clean

@coverage:
    ./scripts/coverage

@test:
    ./scripts/test

@set-pre-push:
    ./scripts/pre-push

@set-pre-commit:
    ./scripts/pre-commit


@serve-app:
    uvicorn app.app:app --reload --port=6969

@serve-docs:
    mkdocs serve

@build-docs:
    mkdocs build

@sys-info:
  @echo "Running on {{arch()}} machine".

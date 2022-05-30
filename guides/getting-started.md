# Getting Started

This guide assumes you are starting with a relatively bare application (for example, no `users` table).
If you wish to install Identity in an app with conflicting tables, additional work will be necessary.
Consider copying and modifying the provided migrations to start from the existing table structure.

## Install

Identity is an Elixir package that provides migrations and other helpers to assist with setup.
It is not currently available on Hex.pm.
For now, install it via GitHub by adding the following to the list of dependencies in `mix.exs` and running `mix deps.get`:

```elixir
def deps do
  [
    {:identity, github: "aj-foster/identity", branch: "main"}
  ]
end
```

## Migrate

After installation, create a new migration to add identity-related tables:

```shell
$ mix ecto.gen.migration add_identity
```

In the generated migration file, add the following:

```elixir
defmodule MyApp.Repo.Migrations.AddIdentity do
  use Ecto.Migration

  def up, do: Identity.Migrations.up()
  def down, do: Identity.Migrations.down()
end
```

Then run the migration:

```shell
$ mix ecto.migrate
```

## Configure

In order to interact with your application's database, Identity needs to know which module contains your database repo.
Following is a minimal configuration added to `config.exs`:

```elixir
config :identity, repo: MyApp.Repo
```

For information about additional configuration options, see `Identity.Config`.

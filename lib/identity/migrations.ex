# COPYRIGHT NOTICE
#
# This code is adapted from a similar module in Oban:
# https://github.com/sorentwo/oban/blob/9b4861354f0189d548f4d5cd89273bc98f8eaede/lib/oban/migrations.ex
#
# It has been modified from its original version to use Identity modules and tables.
#
# The original license can be found here:
# https://github.com/sorentwo/oban/blob/9b4861354f0189d548f4d5cd89273bc98f8eaede/LICENSE.txt
#
# Copyright 2019 Parker Selbert
#
defmodule Identity.Migrations do
  @moduledoc """
  Migrations create and modify the database tables Identity needs to function.

  ## Usage

  To use migrations in your application you'll need to generate an `Ecto.Migration` that wraps
  calls to `Identity.Migrations`:

  ```bash
  mix ecto.gen.migration add_identity
  ```

  Open the generated migration in your editor and call the `up` and `down` functions on
  `Identity.Migrations`:

      defmodule MyApp.Repo.Migrations.AddIdentity do
        use Ecto.Migration

        def up, do: Identity.Migrations.up()
        def down, do: Identity.Migrations.down()
      end

  This will run all of Identity's versioned migrations for your database.
  Now, run the migration to create the table:

  ```bash
  mix ecto.migrate
  ```

  Migrations between versions are idempotent. As new versions are released, you may need to run
  additional migrations.
  To do this, generate a new migration:

  ```bash
  mix ecto.gen.migration upgrade_identity_to_v2
  ```

  Open the generated migration in your editor and call the `up` and `down` functions on
  `Identity.Migrations`, passing a version number:

      defmodule MyApp.Repo.Migrations.UpgradeIdentityToV2 do
        use Ecto.Migration

        def up, do: Identity.Migrations.up(version: 2)
        def down, do: Identity.Migrations.down(version: 2)
      end

  ## Isolation with Prefixes

  Identity supports namespacing through PostgreSQL schemas, also called "prefixes" in Ecto.
  With prefixes your identity tables can reside outside of your primary schema (usually `public`).

  To use a prefix you first have to specify it within your migration:

      defmodule MyApp.Repo.Migrations.AddPrefixedIdentityJobsTable do
        use Ecto.Migration

        def up, do: Identity.Migrations.up(prefix: "private")
        def down, do: Identity.Migrations.down(prefix: "private")
      end

  The migration will create the "private" schema and all tables, functions and triggers within
  that schema.
  With the database migrated you'll then specify the prefix in your configuration:

      config :identity,
        prefix: "private",
        ...

  In some cases, for example if your "private" schema already exists and your database user in
  production doesn't have permissions to create a new schema, trying to create the schema from the
  migration will result in an error.
  In such situations, it may be useful to inhibit the creation of the "private" schema:

      defmodule MyApp.Repo.Migrations.AddPrefixedIdentityJobsTable do
        use Ecto.Migration

        def up, do: Identity.Migrations.up(prefix: "private", create_schema: false)
        def down, do: Identity.Migrations.down(prefix: "private")
      end
  """
  use Ecto.Migration

  @initial_version 1
  @current_version 1
  @default_prefix "public"

  @doc """
  Run the `up` changes for all migrations between the initial version and the current version.

  ## Examples

  Run all migrations up to the current version:

      Identity.Migrations.up()

  Run migrations up to a specified version:

      Identity.Migrations.up(version: 2)

  Run migrations in an alternate prefix:

      Identity.Migrations.up(prefix: "payments")

  Run migrations in an alternate prefix but don't try to create the schema:

      Identity.Migrations.up(prefix: "payments", create_schema: false)
  """
  def up(opts \\ []) when is_list(opts) do
    prefix = Keyword.get(opts, :prefix, @default_prefix)
    version = Keyword.get(opts, :version, @current_version)
    create_schema = Keyword.get(opts, :create_schema, prefix != @default_prefix)
    initial = migrated_version(repo(), prefix)

    cond do
      initial == 0 ->
        change(@initial_version..version, :up, %{prefix: prefix, create_schema: create_schema})

      initial < version ->
        change((initial + 1)..version, :up, %{prefix: prefix})

      true ->
        :ok
    end
  end

  @doc """
  Run the `down` changes for all migrations between the current version and the initial version.

  ## Examples

  Run all migrations from current version down to the first:

      Identity.Migrations.down()

  Run migrations down to and including a specified version:

      Identity.Migrations.down(version: 5)

  Run migrations in an alternate prefix:

      Identity.Migrations.down(prefix: "payments")
  """
  def down(opts \\ []) when is_list(opts) do
    prefix = Keyword.get(opts, :prefix, @default_prefix)
    version = Keyword.get(opts, :version, @initial_version)
    initial = max(migrated_version(repo(), prefix), @initial_version)

    if initial >= version do
      change(initial..version, :down, %{prefix: prefix})
    end
  end

  @doc false
  def initial_version, do: @initial_version

  @doc false
  def current_version, do: @current_version

  @doc false
  def migrated_version(repo, prefix) do
    query = """
    SELECT description
    FROM pg_class
    LEFT JOIN pg_description ON pg_description.objoid = pg_class.oid
    LEFT JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
    WHERE pg_class.relname = 'user_sessions'
    AND pg_namespace.nspname = '#{prefix}'
    """

    case repo.query(query, [], prefix: prefix) do
      {:ok, %{rows: [[version]]}} when is_binary(version) -> String.to_integer(version)
      _ -> 0
    end
  end

  defp change(range, direction, opts) do
    for index <- range do
      pad_idx = String.pad_leading(to_string(index), 2, "0")

      [__MODULE__, "V#{pad_idx}"]
      |> Module.concat()
      |> apply(direction, [opts])
    end

    case direction do
      :up -> record_version(opts, Enum.max(range))
      :down -> record_version(opts, Enum.min(range) - 1)
    end
  end

  defp record_version(_opts, 0), do: :ok

  defp record_version(%{prefix: prefix}, version) do
    execute("COMMENT ON TABLE #{prefix}.user_sessions IS '#{version}'")
  end
end

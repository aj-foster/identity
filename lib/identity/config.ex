defmodule Identity.Config do
  @moduledoc """
  Identity uses application config to specify several options.

      config :identity,
        repo: MyApp.Repo,
        user: MyApp.User

  ## Options

  | Option | Type | Scope | Description |
  | `notifier` | `module` | Runtime | Name of the module that implements the `Identity.Notifier` behaviour. This module will be called to send notifications to users. Default: `Identity.Notifier.Log` |
  | `remember_me` | `keyword` | Runtime | Cookie options for the "remember me" cookie. See `Identity.Plug` for more details. |
  | `repo` | `module` | Runtime | Name of the Ecto.Repo module for your application, for example `MyApp.Repo` |
  | `user` | `module` | Compilation | Name of the module that contains your User schema, for example `MyApp.Accounts.User`. After changing this option, it is necessary to run `mix deps.compile identity --force`. See `Identity.User` for more information. |

  ## Compilation Configuration

  Because of where and when they are used, some configuration options must be specified at compile
  time and may not be changed dynamically during runtime. If you require a compile-time config
  option to be changed at runtime, please reach out to the maintainers with additional information
  about your use case.

  If the `:user` configuration changes, it is necessary to recompile the entire `:identity`
  dependency (not just your application). This can be accomplished by running
  `mix deps.compile identity --force` in each Mix environment. Be aware of this requirement if you
  use cached build artifacts in CI.

  ## Runtime Configuration

  By default, Identity will read all runtime configuration from the Application environment using
  `Application.get_env/3`. This means that runtime configuration can be set in a runtime
  configuration file (such as `runtime.exs`) and changed dynamically using `Application.put_env/4`.

  Looking up data from the Application environment is generally fast enough, even for
  high-throughput operations. However, developers concerned with performance can use `load/1` to
  place Identity's runtime configuration into persistent term storage.

  > #### Warning {:.warning}
  >
  > Persistent Term storage can have severe performance implications if used incorrectly. Roughly
  > speaking, do not call `load/1` if you plan to change any configuration at runtime. See
  > [`:persistent_term`](https://www.erlang.org/doc/man/persistent_term.html) for more information.
  > If performance is this much of a concern, Identity may not make the right trade-offs for your
  > application.

  To accomplish this, call `load/1` during the startup of the application:

      defmodule MyApp.Application do
        use Application

        def start(_type, _args) do
          Identity.Config.load()

          children = [ ... ]

          opts = [strategy: :one_for_one, name: MyApp.Supervisor]
          Supervisor.start_link(children, opts)
        end
      end

  Once configuration has been loaded in this way, calling `Application.put_env/4` will have no
  effect.
  """

  @default_notifier Identity.Notifier.Log
  @key_notifier :notifier
  @key_repo :repo

  @doc """
  Load runtime configuration into persistent term storage.

  For each runtime configuration key, values will be used in this order:

    1. `config` passed directly to this function
    2. `Application.get_env/3` from runtime configuration (for example, `runtime.exs`)
    3. Default value (or raise an error if no default is available)

  See the **Runtime Configuration** section above for more information.
  """
  @spec load(keyword) :: :ok | no_return
  def load(config \\ []) do
    :persistent_term.put(
      {Identity, @key_notifier},
      config(config, @key_notifier, @default_notifier)
    )

    :persistent_term.put({Identity, @key_repo}, config!(config, @key_repo))

    :ok
  end

  @spec config(keyword, atom, any) :: any
  defp config(config, key, default \\ nil) do
    Keyword.get(config, key, Application.get_env(:identity, key, default))
  end

  @spec config!(keyword, atom) :: any | no_return
  defp config!(config, key) do
    config(config, key) || raise "Required configuration `#{key}` missing for Identity"
  end

  @doc false
  defmacro notifier do
    quote do
      :persistent_term.get(
        {Identity, unquote(@key_notifier)},
        Application.get_env(:identity, unquote(@key_notifier), unquote(@default_notifier))
      )
    end
  end

  @doc false
  defmacro repo do
    quote do
      :persistent_term.get(
        {Identity, unquote(@key_repo)},
        Application.get_env(:identity, unquote(@key_repo))
      ) ||
        raise "Required configuration `repo` missing for Identity"
    end
  end

  @doc false
  defmacro user_schema do
    quote do
      Application.compile_env(:identity, :user, Identity.User)
    end
  end
end

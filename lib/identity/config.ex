defmodule Identity.Config do
  @moduledoc """
  Identity uses application config to specify several options.

      config :identity,
        repo: MyApp.Repo,
        user: MyApp.User

  ## Options

  | Option | Type | Description |
  | `notifier` | `module` | Name of the module that implements the `Identity.Notifier` behaviour. This module will be called to send notifications to users. Default: `Identity.Notifier.Log` |
  | `remember_me` | `keyword` | Cookie options for the "remember me" cookie. See `Identity.Plug` for more details. |
  | `repo` | `module` | Name of the Ecto.Repo module for your application, for example `MyApp.Repo`. |
  | `user` | `module` | Name of the module that contains your User schema, for example `MyApp.Accounts.User`. See `Identity.User` for more information. |

  ## Persistent Configuration

  By default, Identity will store configuration using `:persistent_term` the first time it is used
  during runtime. This means that changing the configuration in the application environment will
  not automatically change the library's behaviour. If it is necessary to reload configuration
  from the application environment, call `reload/1`.


  > #### Warning {:.warning}
  >
  > Persistent Term storage can have severe performance implications if used incorrectly. See
  > [`:persistent_term`](https://www.erlang.org/doc/man/persistent_term.html) for more information.
  """

  @default_notifier Identity.Notifier.Log
  @default_user Identity.User
  @key_notifier :notifier
  @key_repo :repo
  @key_user :user

  @doc """
  Reload runtime configuration into persistent term storage.

  For each runtime configuration key, values will be used in this order:

    1. `config` passed directly to this function
    2. `Application.get_env/3` from runtime configuration (for example, `runtime.exs`)
    3. Default value (or raise an error if no default is available)

  See the **Runtime Configuration** section above for more information.
  """
  @spec reload(keyword) :: :ok | no_return
  def reload(config \\ []) do
    :persistent_term.put(
      {Identity, @key_notifier},
      config(config, @key_notifier, @default_notifier)
    )

    :persistent_term.put({Identity, @key_repo}, config!(config, @key_repo))

    :persistent_term.put(
      {Identity, @key_user},
      config(config, @key_user, @default_user)
    )

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
      if value = :persistent_term.get({Identity, unquote(@key_notifier)}, nil) do
        value
      else
        value = Application.get_env(:identity, unquote(@key_notifier), unquote(@default_notifier))
        :persistent_term.put({Identity, unquote(@key_notifier)}, value)
        value
      end
    end
  end

  @doc false
  defmacro repo do
    quote do
      if value = :persistent_term.get({Identity, unquote(@key_repo)}, nil) do
        value
      else
        if value = Application.get_env(:identity, unquote(@key_repo)) do
          :persistent_term.put({Identity, unquote(@key_repo)}, value)
          value
        else
          raise "Required configuration `repo` missing for Identity"
        end
      end
    end
  end

  @doc false
  defmacro user_schema do
    quote do
      if value = :persistent_term.get({Identity, unquote(@key_user)}, nil) do
        value
      else
        value = Application.get_env(:identity, unquote(@key_user), unquote(@default_user))
        :persistent_term.put({Identity, unquote(@key_user)}, value)
        value
      end
    end
  end

  @doc false
  defmacro compile_time_user_schema do
    quote do
      Application.compile_env(:identity, unquote(@key_user), unquote(@default_user))
    end
  end
end

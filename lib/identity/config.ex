defmodule Identity.Config do
  @moduledoc """
  Identity uses application config to specify several options.

      config :identity,
        repo: MyApp.Repo,
        user: MyApp.User

  ## Options

  Because of where and when they are used, some configuration options must be specified at compile
  time and may not be changed dynamically during runtime. If you require a compile-time config
  option to be changed at runtime, please reach out to the maintainers with additional information
  about your use-case.

  | Option | Type | Scope | Description |
  | `repo` | `module` | Compilation | Name of the Ecto.Repo module for your application, for example `MyApp.Repo` |
  | `user` | `module` | Compilation | Name of the module that contains your User schema, for example `MyApp.Accounts.User`. This schema must have a UUID primary key called `id`. |
  """
end

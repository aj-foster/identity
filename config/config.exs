# Note: This file is for testing configuration only.
import Config

config :identity, Identity.Test.Endpoint,
  check_origin: false,
  code_reloader: false,
  debug_errors: true,
  http: [port: 4000],
  secret_key_base: "secret",
  server: true,
  url: [host: "localhost"]

config :identity, Identity.Test.Repo,
  name: Identity.Test.Repo,
  priv: "test/support/",
  url: System.get_env("DATABASE_URL") || "postgres://localhost:5432/identity_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :identity,
  ecto_repos: [Identity.Test.Repo],
  notifier: Identity.Test.Notifier,
  repo: Identity.Test.Repo

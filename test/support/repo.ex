defmodule Identity.Test.Repo do
  use Ecto.Repo,
    otp_app: :identity,
    adapter: Ecto.Adapters.Postgres
end

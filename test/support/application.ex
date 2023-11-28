defmodule Identity.Test.Application do
  @moduledoc false
  use Application

  def start(_type, _args) do
    Logger.configure(level: :warning)
    Identity.Config.load()

    children = [
      Identity.Test.Repo,
      Identity.Test.Endpoint
    ]

    opts = [strategy: :one_for_one, name: Identity.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

defmodule Identity.Test.Application do
  @moduledoc false
  use Application

  def start(_type, _args) do
    Logger.configure(level: :warn)

    children = [
      Identity.Test.Repo
    ]

    opts = [strategy: :one_for_one, name: Identity.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

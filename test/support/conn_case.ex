defmodule Identity.ConnCase do
  @moduledoc "Provides easy setup for tests that require a Plug connection."
  use ExUnit.CaseTemplate

  using do
    quote do
      alias Identity.Test.Factory
      alias Identity.Test.Repo

      import Plug.Conn
      import Phoenix.ConnTest

      @endpoint Identity.Test.Endpoint
    end
  end

  setup tags do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Identity.Test.Repo, shared: not tags[:async])

    on_exit(fn ->
      Ecto.Adapters.SQL.Sandbox.stop_owner(pid)
    end)

    :ok
  end

  setup do
    conn =
      Phoenix.ConnTest.build_conn()
      |> Map.replace!(:secret_key_base, "secret")
      |> Plug.Test.init_test_session(%{})

    user = Identity.Test.Factory.insert(:user)

    %{conn: conn, user: user}
  end
end

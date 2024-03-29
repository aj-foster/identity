defmodule Identity.DataCase do
  @moduledoc "Provides easy setup for tests that require access to the database."
  use ExUnit.CaseTemplate

  using do
    quote do
      alias Identity.Test.Factory
      alias Identity.Test.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Identity.DataCase
    end
  end

  setup tags do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Identity.Test.Repo, shared: not tags[:async])

    on_exit(fn ->
      Ecto.Adapters.SQL.Sandbox.stop_owner(pid)
    end)

    :ok
  end

  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end

if Code.ensure_loaded?(Phoenix.Controller) do
  defmodule Identity.Controller do
    @moduledoc """
    Provides Phoenix controller actions for common identity-related actions.
    """
    use Phoenix.Controller, put_default_views: false, namespace: Identity

    alias Plug.Conn

    plug :put_new_view, Identity.Phoenix.View

    @doc "Render a login form with no active error message."
    @spec new_session(Conn.t(), Conn.params()) :: Conn.t()
    def new_session(conn, _params) do
      routes = :"#{router_module(conn)}.Helpers"
      render(conn, "new_session.html", error: nil, routes: routes)
    end
  end
end

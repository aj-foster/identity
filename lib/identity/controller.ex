if Code.ensure_loaded?(Phoenix.Controller) do
  defmodule Identity.Controller do
    @moduledoc """
    Provides Phoenix controller actions for common identity-related actions.
    """
    use Phoenix.Controller, put_default_views: false, namespace: Identity

    alias Plug.Conn

    @session_2fa_pending :session_2fa_pending
    @session_remember_me_pending :session_remember_me_pending

    plug :put_new_view, Identity.Phoenix.View

    @doc "Render a login form with no active error message."
    @spec new_session(Conn.t(), Conn.params()) :: Conn.t()
    def new_session(conn, _params) do
      routes = :"#{router_module(conn)}.Helpers"
      render(conn, "new_session.html", error: nil, routes: routes)
    end

    @doc """
    Validate login details and either login or redirect to enter 2FA code.

    Incoming params should have the form:

        %{
          "session" => %{
            "email" => email,
            "password" => password,
            "remember_me" => remember_me  # Optional, "true" when desired
          }
        }

    In the event of a login failure, the user will see `new_session.html` with a generic error
    message to prevent account enumeration.
    """
    @spec create_session(Conn.t(), Conn.params()) :: Conn.t()
    def create_session(conn, %{"session" => session_params}) do
      %{"email" => email, "password" => password} = session_params
      remember_me = session_params["remember_me"] == "true"
      routes = :"#{router_module(conn)}.Helpers"

      if user = Identity.get_user_by_email_and_password(email, password) do
        # TODO: Can we preload the login on the user?
        if Identity.enabled_2fa?(user) do
          conn
          |> Identity.Plug.log_in_user(user, remember_me: false)
          |> put_session(@session_2fa_pending, true)
          |> put_session(@session_remember_me_pending, remember_me)
          |> redirect(to: routes.identity_path(conn, :new_2fa))
        else
          Identity.Plug.log_in_and_redirect_user(conn, user, remember_me: remember_me)
        end
      else
        routes = :"#{router_module(conn)}.Helpers"
        render(conn, "new_session.html", error: "Invalid e-mail or password", routes: routes)
      end
    end

    @doc "Render a 2FA form with no active error message."
    @spec new_2fa(Conn.t(), Conn.params()) :: Conn.t()
    def new_2fa(conn, _params) do
      routes = :"#{router_module(conn)}.Helpers"
      render(conn, "new_2fa.html", error: nil, routes: routes)
    end
  end
end

if Code.ensure_loaded?(Phoenix.Controller) do
  defmodule Identity.Controller do
    @moduledoc """
    Provides Phoenix controller actions for common identity-related actions.
    """
    use Phoenix.Controller, put_default_views: false, namespace: Identity

    alias Plug.Conn

    @session_2fa_pending :session_2fa_pending

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
            "remember_me" => remember_me  # Optional
          }
        }

    In the event of a login failure, the user will see `new_session.html` with a generic error
    message to prevent account enumeration.
    """
    @spec create_session(Conn.t(), Conn.params()) :: Conn.t()
    def create_session(conn, %{"session" => session_params}) do
      routes = :"#{router_module(conn)}.Helpers"
      %{"email" => email, "password" => password} = session_params

      if user = Identity.get_user_by_email_and_password(email, password) do
        # TODO: Can we preload the login on the user?
        if Identity.enabled_2fa?(user) do
          post_2fa_params = Map.take(session_params, ["remember_me"])

          conn
          |> Identity.Plug.log_in_user(user, remember_me: false)
          |> put_session(@session_2fa_pending, true)
          |> redirect(to: routes.identity_path(conn, :new_2fa, user: post_2fa_params))
        else
          remember_me = session_params["remember_me"] == "true"
          Identity.Plug.log_in_and_redirect_user(conn, user, remember_me: remember_me)
        end
      else
        routes = :"#{router_module(conn)}.Helpers"
        render(conn, "new_session.html", error: "Invalid e-mail or password", routes: routes)
      end
    end
  end
end

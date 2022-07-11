if Code.ensure_loaded?(Phoenix.Controller) do
  defmodule Identity.Controller do
    @moduledoc """
    Provides Phoenix controller actions for common identity-related actions.

    This module is part of a [Progressive Replacement](guides/progressive-replacement.md) plan. See
    that document for examples of the various ways to use this functionality.
    """
    use Phoenix.Controller, put_default_views: false, namespace: Identity
    import Identity.Plug

    alias Plug.Conn

    @session_remember_me_pending :session_remember_me_pending

    plug :fetch_session
    plug :fetch_flash
    plug :put_new_view, Identity.Phoenix.View

    plug :redirect_if_user_is_authenticated
         when action in [:new_session, :create_session, :new_2fa, :validate_2fa]

    plug :require_pending_login when action in [:new_2fa, :validate_2fa]
    plug :fetch_current_user when action in [:validate_2fa]

    #
    # Password Login
    #

    @doc """
    Render a login form with no active error message.

    This action provides a traditional, distinct login page for password-based logins. This action
    may not be necessary if all logins occur through another route, for example the app's home page.

    Renders `new_session.html` with assigns `error: nil` and `routes` with the endpoint's route
    helper module.
    """
    @doc section: :session
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
    message (set using the `:error` assign) to prevent account enumeration.
    """
    @doc section: :session
    @spec create_session(Conn.t(), Conn.params()) :: Conn.t()
    def create_session(conn, %{"session" => session_params}) do
      %{"email" => email, "password" => password} = session_params
      remember_me = session_params["remember_me"] == "true"
      routes = :"#{router_module(conn)}.Helpers"

      if user = Identity.get_user_by_email_and_password(email, password) do
        # TODO: Can we preload the login on the user?
        if Identity.enabled_2fa?(user) do
          conn
          |> Identity.Plug.log_in_user(user, remember_me: false, pending: true)
          |> put_session(@session_remember_me_pending, remember_me)
          |> redirect(to: routes.identity_path(conn, :new_2fa))
        else
          conn
          |> put_flash(:info, "Successfully logged in")
          |> Identity.Plug.log_in_and_redirect_user(user, remember_me: remember_me)
        end
      else
        routes = :"#{router_module(conn)}.Helpers"
        render(conn, "new_session.html", error: "Invalid e-mail or password", routes: routes)
      end
    end

    #
    # Two-Factor Authentication
    #

    @doc "Render a 2FA form with no active error message."
    @doc section: :mfa
    @spec new_2fa(Conn.t(), Conn.params()) :: Conn.t()
    def new_2fa(conn, _params) do
      routes = :"#{router_module(conn)}.Helpers"
      render(conn, "new_2fa.html", error: nil, routes: routes)
    end

    @doc """
    Validate 2FA details and login the user.

    Incoming params should have the form:

        %{
          "session" => %{
            "code" => code  # Either 2FA code or backup code
          }
        }

    In the event of a login failure, the user will see `new_2fa.html` with an error message set
    using the `:error` assign.
    """
    @doc section: :mfa
    @spec validate_2fa(Conn.t(), Conn.params()) :: Conn.t()
    def validate_2fa(conn, %{"session" => %{"code" => code}}) do
      user = conn.assigns[:current_user]
      remember_me = get_session(conn, @session_remember_me_pending)

      if Identity.valid_2fa?(user, code) do
        conn
        |> delete_session(@session_remember_me_pending)
        |> put_flash(:info, "Successfully logged in")
        |> Identity.Plug.log_in_and_redirect_user(user, remember_me: remember_me)
      else
        routes = :"#{router_module(conn)}.Helpers"

        render(conn, "new_2fa.html",
          error: "Invalid two-factor authentication code",
          routes: routes
        )
      end
    end
  end
end

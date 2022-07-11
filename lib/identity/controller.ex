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

    @assign_password_reset_user :password_reset_user
    @session_remember_me_pending :session_remember_me_pending

    plug :fetch_session
    plug :fetch_flash
    plug :put_new_view, Identity.Phoenix.View

    plug :redirect_if_user_is_authenticated
         when action in [:new_session, :create_session, :new_2fa, :validate_2fa]

    plug :require_pending_login when action in [:new_2fa, :validate_2fa]
    plug :fetch_current_user when action in [:validate_2fa]

    plug :get_user_by_password_token when action in [:new_password, :update_password]

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
      routes = Module.concat(router_module(conn), Helpers)
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
      routes = Module.concat(router_module(conn), Helpers)

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
        routes = Module.concat(router_module(conn), Helpers)
        render(conn, "new_session.html", error: "Invalid e-mail or password", routes: routes)
      end
    end

    #
    # Two-Factor Authentication
    #

    @doc """
    Render a 2FA form with no active error message.

    This action provides a traditional, distinct 2FA page for password-based logins.

    Renders `new_2fa.html` with assigns `error: nil` and `routes` with the endpoint's route
    helper module.
    """
    @doc section: :mfa
    @spec new_2fa(Conn.t(), Conn.params()) :: Conn.t()
    def new_2fa(conn, _params) do
      routes = Module.concat(router_module(conn), Helpers)
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
    using the `:error` assign and `:routes` with the endpoint's route helper module.
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
        routes = Module.concat(router_module(conn), Helpers)

        render(conn, "new_2fa.html",
          error: "Invalid two-factor authentication code",
          routes: routes
        )
      end
    end

    #
    # Reset Password
    #

    @doc """
    Render a password reset request form with no active error message.

    This action provides a traditional, distinct form for starting the password reset process.

    Renders `new_password_token.html` with assigns `error: nil` and `routes` with the endpoint's
    route helper module.
    """
    @doc section: :password
    @spec new_password_token(Conn.t(), Conn.params()) :: Conn.t()
    def new_password_token(conn, _params) do
      routes = Module.concat(router_module(conn), Helpers)
      render(conn, "new_password_token.html", error: nil, routes: routes)
    end

    @doc """
    Create and send a new password reset token for the user with the given `email`.

    See `Identity.request_password_reset/1` for more information.

    Incoming params should have the form:

    %{
      "password_token" => %{
        "email" => email
      }
    }

    Regardless of outcome, redirects to `"/"` with a generic message to prevent account enumeration.
    """
    @doc section: :password
    @spec create_password_token(Conn.t(), Conn.params()) :: Conn.t()
    def create_password_token(conn, %{"password_token" => %{"email" => email}}) do
      if user = Identity.get_user_by_email(email) do
        Identity.request_password_reset(user)
      end

      put_flash(
        conn,
        :info,
        "If your email is in our system, you will receive instructions to reset your password shortly."
      )
      |> redirect(to: "/")
    end

    @doc """
    Render a password reset form with no active error message.

    This action provides a traditional, distinct form for completing the password reset process.

    TODO
    Renders `new_password.html` with assigns `error: nil` and `routes` with the endpoint's route
    helper module. The rendered form must resubmit the original password reset token.
    """
    @doc section: :password
    @spec new_password(Conn.t(), Conn.params()) :: Conn.t()
    def new_password(conn, _params) do
      routes = Module.concat(router_module(conn), Helpers)
      user = conn.assigns[@assign_password_reset_user]

      render(conn, "new_password.html",
        changeset: Identity.request_password_change(user),
        routes: routes
      )
    end

    @doc """
    Change the user's password using a password reset token.
    """
    @doc section: :password
    @spec update_password(Conn.t(), Conn.params()) :: Conn.t()
    def update_password(conn, %{"password" => password_params}) do
      routes = Module.concat(router_module(conn), Helpers)
      user = conn.assigns[@assign_password_reset_user]

      case Identity.reset_password(user, password_params) do
        {:ok, _} ->
          conn
          |> put_flash(:info, "Password reset successfully.")
          |> redirect(to: routes.identity_path(conn, :new_session))

        {:error, changeset} ->
          render(conn, "new_password.html", changeset: changeset, routes: routes)
      end
    end

    @spec get_user_by_password_token(Plug.Conn.t(), any) :: Plug.Conn.t()
    defp get_user_by_password_token(conn, _opts) do
      %{"token" => token} = conn.params

      if user = Identity.get_user_by_password_token(token) do
        conn
        |> assign(@assign_password_reset_user, user)
        |> assign(:token, token)
      else
        conn
        |> put_flash(:error, "Reset password link is invalid or it has expired.")
        |> redirect(to: "/")
        |> halt()
      end
    end
  end
end

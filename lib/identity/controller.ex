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

    plug :fetch_current_user
    plug :get_user_by_password_token when action in [:new_password, :update_password]

    plug :redirect_if_user_is_authenticated
         when action in [:new_session, :create_session, :new_2fa, :validate_2fa]

    plug :require_pending_login when action in [:new_2fa, :validate_2fa]
    plug :require_authenticated_user when action in [:new_email, :create_email, :confirm_email]

    #
    # Password Login
    #

    @doc """
    Render a login form with no active error message.

    This action provides a traditional, distinct login page for password-based logins. This action
    may not be necessary if all logins occur through another route, for example the app's home page.

    ## Incoming Params

    This action has no incoming params.

    ## Render

    Renders `new_session.html` with the following assigns:

      * `:error` (string or `nil`): Error message to display. For this action, always `nil`.

    """
    @doc section: :session
    @spec new_session(Conn.t(), Conn.params()) :: Conn.t()
    def new_session(conn, _params) do
      render(conn, "new_session.html", error: nil)
    end

    @doc """
    Validate login details and either login or redirect to enter 2FA code.

    ## Incoming Params

        %{
          "session" => %{
            "email" => email,
            "password" => password,
            "remember_me" => remember_me  # Optional, "true" when desired
          }
        }

    ## Error Response

    In the event of a login failure, renders `new_session.html` with:

      * `:error` (string or `nil`): Generic error message, which doesn't specify whether the email
        or password is incorrect, to avoid account enumeration.

    """
    @doc section: :session
    @spec create_session(Conn.t(), Conn.params()) :: Conn.t()
    def create_session(conn, %{"session" => session_params}) do
      %{"email" => email, "password" => password} = session_params
      remember_me = session_params["remember_me"] == "true"

      if user = Identity.get_user_by_email_and_password(email, password) do
        # TODO: Can we preload the login on the user?
        if Identity.enabled_2fa?(user) do
          routes = Module.concat(router_module(conn), Helpers)

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
        render(conn, "new_session.html", error: "Invalid e-mail or password")
      end
    end

    #
    # Two-Factor Authentication
    #

    @doc """
    Render a 2FA form with no active error message.

    ## Incoming Params

    This action has no incoming params.

    ## Render

    Renders `new_2fa.html` with the following assigns:

      * `:error` (string or `nil`): Error message to display. For this action, always `nil`.

    """
    @doc section: :mfa
    @spec new_2fa(Conn.t(), Conn.params()) :: Conn.t()
    def new_2fa(conn, _params) do
      render(conn, "new_2fa.html", error: nil)
    end

    @doc """
    Validate 2FA details and login the user.

    ## Incoming Params

        %{
          "session" => %{
            "code" => code  # Either 2FA code or backup code
          }
        }

    ## Error Response

    In the event of a login failure, renders `new_2fa.html` with:

      * `:error` (string or `nil`): Error message about the invalid code.

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
        render(conn, "new_2fa.html", error: "Invalid two-factor authentication code")
      end
    end

    #
    # Reset Password
    #

    @doc """
    Render a password reset request form with no active error message.

    ## Incoming Params

    This action has no incoming params.

    ## Render

    Renders `new_password_token.html` with the following assigns:

      * `:error` (string or `nil`): Error message to display. For this action, always `nil`.

    """
    @doc section: :password_reset
    @spec new_password_token(Conn.t(), Conn.params()) :: Conn.t()
    def new_password_token(conn, _params) do
      render(conn, "new_password_token.html", error: nil)
    end

    @doc """
    Create and send a new password reset token for the user with the given `email`.

    This action uses the `c:Identity.Notifier.reset_password/2` callback to notify the user of the
    new token.

    ## Incoming Params

        %{
          "password_token" => %{
            "email" => email
          }
        }

    ## Response

    Regardless of outcome, redirects to `"/"` with a generic informational flash message to prevent
    account enumeration.
    """
    @doc section: :password_reset
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
    Render a password change form with no active error message.

    ## Incoming Params

        %{
          "token" => token  # Password reset token, generally included as a URL param
        }

    ## Render

    Renders `new_password.html` with the following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for changing the user's password. Expects fields
        `password` and `password_confirmation`.

    """
    @doc section: :password_reset
    @spec new_password(Conn.t(), Conn.params()) :: Conn.t()
    def new_password(conn, _params) do
      user = conn.assigns[@assign_password_reset_user]
      render(conn, "new_password.html", changeset: Identity.request_password_change(user))
    end

    @doc """
    Update the user's password using a password reset token.

    ## Incoming Params

        %{
          "token" => token,  # Password reset token, generally included as a URL param
          "password" => %{
            "password" => password,
            "password_confirmation" => password
          }
        }

    ## Success Response

    Redirects to the login route (`:new_session`) to avoid disclosing the email address if someone
    has a leaked token.

    ## Error Response

    In the event of an update failure, renders `new_password.html` with the following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for changing the user's password. Expects fields
        `password` and `password_confirmation`.

    """
    @doc section: :password_reset
    @spec update_password(Conn.t(), Conn.params()) :: Conn.t()
    def update_password(conn, %{"password" => password_params}) do
      user = conn.assigns[@assign_password_reset_user]

      case Identity.reset_password(user, password_params) do
        {:ok, _} ->
          routes = Module.concat(router_module(conn), Helpers)

          conn
          |> put_flash(:info, "Password reset successfully.")
          |> redirect(to: routes.identity_path(conn, :new_session))

        {:error, changeset} ->
          render(conn, "new_password.html", changeset: changeset)
      end
    end

    # Helper plug for password reset actions.
    @spec get_user_by_password_token(Conn.t(), any) :: Conn.t()
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

    #
    # Email Addresses
    #

    @doc """
    Render a form to add an additional email address to an existing user.

    ## Incoming Params

    This action has no incoming params.

    ## Render

    Renders `new_email.html` with the following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for adding a new email address. Expects fields
        `email` and `password` (for verification).

    """
    @doc section: :email
    @spec new_email(Conn.t(), any) :: Conn.t()
    def new_email(conn, _params) do
      render(conn, "new_email.html", changeset: Identity.request_register_email())
    end

    @doc """
    Create a new email address for the current user and send a confirmation notification.

    ## Incoming Params

        %{
          "email" => %{
            "email" => email,
            "password" => password  # For verification
          }
        }

    ## Success Response

    Redirects to the new email route with a flash message informing the user to check their email
    for a confirmation link.

    ## Error Response

    In the event of an incorrect password or update failure, renders `new_email.html` with the
    following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for adding a new email address. Expects fields
        `email` and `password` (for verification).

    """
    @doc section: :email
    @spec create_email(Conn.t(), Conn.params()) :: Conn.t()
    def create_email(conn, %{"email" => %{"email" => email, "password" => password}}) do
      user = conn.assigns[:current_user]

      case Identity.register_email(user, email, password) do
        :ok ->
          routes = Module.concat(router_module(conn), Helpers)

          conn
          |> put_flash(:info, "A link to confirm your email has been sent to the new address.")
          |> redirect(to: routes.identity_path(conn, :new_email))

        {:error, changeset} ->
          render(conn, "new_email.html", changeset: changeset)
      end
    end

    @doc """
    Verify a newly registered email address using an email confirmation token.

    ## Incoming Params

        %{
          "token" => token  # Email confirmation token, generally included as a URL param
        }

    ## Success Response

    Redirects to `"/"` with an informational flash message.

    ## Error Response

    In the event of an invalid token, redirects to `"/"` with an informational flash message.
    """
    @doc section: :email
    @spec confirm_email(Conn.t(), Conn.params()) :: Conn.t()
    def confirm_email(conn, %{"token" => token}) do
      case Identity.confirm_email(token) do
        {:ok, _email} ->
          conn
          |> put_flash(:info, "Email address confirmed")
          |> redirect(to: "/")

        {:error, _reason} ->
          conn
          |> put_flash(:error, "Email confirmation link is invalid or it has expired")
          |> redirect(to: "/")
      end
    end
  end
end

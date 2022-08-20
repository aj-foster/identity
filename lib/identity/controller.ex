if Code.ensure_loaded?(Phoenix.Controller) do
  defmodule Identity.Controller do
    @moduledoc """
    Provides Phoenix controller actions for common identity-related actions.

    > #### Note {:.info}
    > This module is part of a [Progressive Replacement](guides/progressive-replacement.md) plan.
    > See that document for examples of the various ways to use this functionality.

    ## Routes

    If you're looking to get off the ground running quickly, you can add all of the following to
    your application's router and take advantage of this module and the provided templates:

        # [Method] [Path], [Controller], [Action], [Options]

        # Session
        get "/session/new", Identity.Controller, :new_session, as: :identity
        post "/session/new", Identity.Controller, :create_session, as: :identity

        get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity
        post "/session/2fa", Identity.Controller, :validate_2fa, as: :identity

        delete "/session", Identity.Controller, :delete_session, as: :identity

        # Password Reset
        get "/password/new", Identity.Controller, :new_password_token, as: :identity
        post "/password/new", Identity.Controller, :create_password_token, as: :identity

        get "/password/:token", Identity.Controller, :new_password, as: :identity
        put "/password/:token", Identity.Controller, :create_password, as: :identity

        # Email Addresses
        get "/email/new", Identity.Controller, :new_email, as: :identity
        post "/email/new", Identity.Controller, :create_email, as: :identity
        get "/email/:token", Identity.Controller, :confirm_email, as: :identity
        delete "/user/email", Identity.Controller, :delete_email, as: :identity

        # User Registration
        get "/user/new", Identity.Controller, :new_user, as: :identity
        post "/user/new", Identity.Controller, :create_user, as: :identity

        # User Settings
        get "/user/password", Identity.Controller, :edit_password, as: :identity
        put "/user/password", Identity.Controller, :update_password, as: :identity

        get "/user/2fa/new", Identity.Controller, :new_2fa, as: :identity
        post "/user/2fa/new", Identity.Controller, :create_2fa, as: :identity
        get "/user/2fa", Identity.Controller, :show_2fa, as: :identity
        delete "/user/2fa", Identity.Controller, :delete_2fa, as: :identity
        put "/user/2fa/backup", Identity.Controller, :regenerate_2fa, as: :identity

        # OAuth: these paths should match the configuration of Ueberauth.
        get "/auth/:provider", Identity.Controller, :oauth_request, as: :identity
        get "/auth/:provider/callback", Identity.Controller, :oauth_callback, as: :identity

    For each route, the path can be modified, but the method, action, and `:as` option should remain
    the same. If you decide to implement an action yourself, simply change the controller.

    It is necessary to keep the action names as they are listed above and provide `as: :identity`
    in order for other parts of the application to find the routes. For example, the
    `create_session` action looks up the 2FA form using the `pending_2fa` and `as: :identity`
    information.

    > #### Important {:.warning}
    > Even if you choose to implement a controller action yourself, you may need to keep the same
    > name and options if you continue to use Identity-provided actions or templates for other
    > routes.

    This trade-off was made deliberately so you can choose any path for each route. Furthermore,
    it is not necessary to enable path helpers in your router.

    ## Custom Views

    Even when you use the Identity-provided controller actions, you may still customize the
    templates that are rendered. To do this, use the `Phoenix.Controller.put_view/2` plug in a
    router pipeline:

        pipeline :custom_view do
          plug :put_view, MyAppWeb.IdentityView
        end

        scope "/" do
          pipe_through :custom_view

          get "/session/new", Identity.Controller, :new_session, as: :identity
          post "/session/new", Identity.Controller, :create_session, as: :identity
          # ...
        end

    The provided controller actions will now render the new view's templates. Make sure your
    templates use the assigns available from each action, and the parameters required for any
    Identity-provided form actions.

    Not ready to replace all of the Identity-provided templates? There's no need. You can add the
    custom view to any subset of the Identity routes, and leave the rest alone.
    """
    import Plug.Conn, except: [delete_session: 2]
    import Phoenix.Controller
    use Phoenix.Controller.Pipeline
    import Identity.Plug
    require Logger

    if Code.ensure_loaded?(Ueberauth) do
      plug Ueberauth
    end

    alias Phoenix.Controller
    alias Plug.Conn
    alias Identity.Phoenix.Util

    @assign_password_reset_user :password_reset_user
    @session_remember_me_pending :session_remember_me_pending

    plug :fetch_session
    plug :fetch_flash
    plug :put_new_view, Identity.Phoenix.View

    plug :fetch_identity
    plug :get_user_by_password_token when action in [:new_password, :create_password]

    plug :redirect_if_authenticated
         when action in [
                :new_session,
                :create_session,
                :pending_2fa,
                :validate_2fa,
                :new_user,
                :create_user
              ]

    plug :require_pending_login when action in [:pending_2fa, :validate_2fa]

    plug :redirect_if_unauthenticated
         when action in [
                :new_email,
                :create_email,
                :confirm_email,
                :edit_password,
                :update_password,
                :show_2fa,
                :new_2fa,
                :create_2fa,
                :delete_2fa,
                :regenerate_2fa
              ]

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
      Controller.render(conn, "new_session.html", error: nil)
    end

    @doc """
    Validate login details and either login or redirect to enter 2FA code.

    ## Incoming Params

        %{
          "session" => %{
            "email" => string,
            "password" => string,
            "remember_me" => "true" | "false"  # Optional, default "false"
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
          conn
          |> Identity.Plug.log_in_user(user, remember_me: false, pending: true)
          |> Conn.put_session(@session_remember_me_pending, remember_me)
          |> Controller.redirect(to: Util.path_for(conn, :pending_2fa))
        else
          conn
          |> Controller.put_flash(:info, "Successfully logged in")
          |> Identity.Plug.log_in_and_redirect_user(user, remember_me: remember_me)
        end
      else
        Controller.render(conn, "new_session.html", error: "Invalid e-mail or password")
      end
    end

    @doc """
    Log out the current user and return to the root route.

    ## Incoming Params

    This action has no incoming params.

    ## Response

    Logs out the current user and redirects to `"/"`.
    """
    @doc section: :session
    @spec delete_session(Conn.t(), any) :: Conn.t()
    def delete_session(conn, _params) do
      conn
      |> Controller.put_flash(:info, "Successfully logged out")
      |> Identity.Plug.log_out_user()
    end

    #
    # Two-Factor Authentication
    #

    @doc """
    Render a 2FA form with no active error message.

    ## Incoming Params

    This action has no incoming params.

    ## Render

    Renders `pending_2fa.html` with the following assigns:

      * `:error` (string or `nil`): Error message to display. For this action, always `nil`.

    """
    @doc section: :mfa
    @spec pending_2fa(Conn.t(), Conn.params()) :: Conn.t()
    def pending_2fa(conn, _params) do
      Controller.render(conn, "pending_2fa.html", error: nil)
    end

    @doc """
    Validate 2FA details and login the user.

    ## Incoming Params

        %{
          "session" => %{
            "code" => string  # Either 2FA code or backup code
          }
        }

    ## Error Response

    In the event of a login failure, renders `pending_2fa.html` with:

      * `:error` (string or `nil`): Error message about the invalid code.

    """
    @doc section: :mfa
    @spec validate_2fa(Conn.t(), Conn.params()) :: Conn.t()
    def validate_2fa(conn, %{"session" => %{"code" => code}}) do
      user = conn.assigns[:current_user]
      remember_me = Conn.get_session(conn, @session_remember_me_pending)

      if Identity.valid_2fa?(user, code) do
        conn
        |> Plug.Conn.delete_session(@session_remember_me_pending)
        |> Controller.put_flash(:info, "Successfully logged in")
        |> Identity.Plug.log_in_and_redirect_user(user, remember_me: remember_me)
      else
        Controller.render(conn, "pending_2fa.html",
          error: "Invalid two-factor authentication code"
        )
      end
    end

    @doc """
    Display the current status of two-factor authentication for the current user.

    ## Incoming Params

    This action has no incoming params.

    ## Render

    Renders `show_2fa.html` with the following assigns:

      * `:enabled?` (boolean): Whether 2FA is enabled for the current user.

    """
    @doc section: :mfa
    @spec show_2fa(Conn.t(), any) :: Conn.t()
    def show_2fa(conn, _params) do
      user = conn.assigns[:current_user]
      enabled? = Identity.enabled_2fa?(user)
      codes_remaining = Identity.count_2fa_backup_codes(user)
      render(conn, "show_2fa.html", enabled?: enabled?, codes_remaining: codes_remaining)
    end

    if Code.ensure_loaded?(NimbleTOTP) do
      @doc """
      Render a form for enabling 2FA.

      Generating the two-factor secret requires the optional `NimbleTOTP` dependency, and displaying
      a QR code requires the optional `EQRCode` dependency.

      ## Incoming Params

      This action has no incoming params.

      ## Render

      Renders `new_2fa.html` with the following assigns:

        * `:changeset` (`Ecto.Changeset`): Changeset for enabling 2FA. Expects two fields,
          `otp_code` with a verification code and `otp_secret` with the base-32 encoded (no padding)
          secret used to generate the QR code.

        * `:otp_uri` (string): OTP setup URI.

        * `:otp_secret` (string): Base-32 encoded (no padding) OTP secret, to be returned as a
          hidden input along with the verification code.

        * `:qr_code` (HTML raw): OTP setup QR code, encoded as an SVG using `Phoenix.HTML.raw/1`.

      """
      @doc section: :mfa
      @spec new_2fa(Conn.t(), any) :: Conn.t()
      def new_2fa(conn, _params) do
        user = conn.assigns[:current_user]

        if Identity.enabled_2fa?(user) do
          conn
          |> Controller.put_flash(:info, "Two-factor authentication is already enabled")
          |> Controller.redirect(to: Util.path_for(conn, :show_2fa))
        else
          changeset = Identity.enable_2fa_changeset()
          otp_secret = Ecto.Changeset.get_field(changeset, :otp_secret)
          otp_uri = NimbleTOTP.otpauth_uri("Identity:#{user.id}", otp_secret)

          qr_code =
            otp_uri
            |> encode_qr_code()
            |> Phoenix.HTML.raw()

          Controller.render(conn, "new_2fa.html",
            changeset: changeset,
            otp_uri: otp_uri,
            otp_secret: Base.encode32(otp_secret, padding: false),
            qr_code: qr_code
          )
        end
      end

      @doc """
      Enable 2FA for the current user.

      ## Incoming Params

      This action requires knowledge of the original OTP secret that was used to generate a QR
      code or OTP URI for the user. This is most likely passed back to the controller using a
      hidden input. The value must be base-32 encoded (with no padding) for safety.

      Note the key is `mfa` because `2fa` is not a valid atom when using the form helper.

          %{
            "mfa" => %{
              "otp_code" => string,
              "otp_secret" => string  # Base-32 encoded, no padding
            }
          }

      ## Success Response

      Renders `show_2fa_codes.html` with a success message and the following assign:

        * `:codes` (list of strings): Newly-generated backup codes for two-factor authentication
          without the second device.

      ## Error Response

      In the event of a verification failure, renders `new_2fa.html` with the following assigns:

        * `:changeset` (`Ecto.Changeset`): Changeset for enabling 2FA. Expects two fields,
          `otp_code` with a verification code and `otp_secret` with the base-32 encoded (no padding)
          secret used to generate the QR code.

        * `:otp_uri` (string): OTP setup URI.

        * `:otp_secret` (string): Base-32 encoded (no padding) OTP secret, to be returned as a
          hidden input along with the verification code.

        * `:qr_code` (HTML raw): OTP setup QR code, encoded as an SVG using `Phoenix.HTML.raw/1`.

      """
      @doc section: :mfa
      @spec create_2fa(Conn.t(), Conn.params()) :: Conn.t()
      def create_2fa(conn, %{"mfa" => params}) do
        user = conn.assigns[:current_user]

        if Identity.enabled_2fa?(user) do
          conn
          |> Controller.put_flash(:info, "Two-factor authentication is already enabled")
          |> Controller.redirect(to: Util.path_for(conn, :show_2fa))
        else
          params =
            Map.update(params, "otp_secret", nil, fn secret ->
              case Base.decode32(secret, padding: false) do
                {:ok, secret} -> secret
                :error -> nil
              end
            end)

          case Identity.enable_2fa(user, params) do
            {:ok, backup_codes} ->
              conn
              |> Controller.put_flash(:info, "Two-factor authentication enabled")
              |> Controller.render("show_2fa_codes.html", codes: backup_codes)

            {:error, changeset} ->
              new_changeset = Identity.enable_2fa_changeset()
              otp_secret = Ecto.Changeset.get_field(new_changeset, :otp_secret)
              otp_uri = NimbleTOTP.otpauth_uri("Identity:#{user.id}", otp_secret)

              qr_code =
                otp_uri
                |> encode_qr_code()
                |> Phoenix.HTML.raw()

              conn
              |> Controller.put_flash(
                :error,
                "Verification code invalid. Please try again with this new code."
              )
              |> Controller.render("new_2fa.html",
                changeset: changeset,
                otp_uri: otp_uri,
                otp_secret: Base.encode32(otp_secret, padding: false),
                qr_code: qr_code
              )
          end
        end
      end

      @doc """
      Disable 2FA for the current user.

      ## Incoming Params

      This action has no incoming params.

      ## Response

      Redirects to the show 2FA route with a success or failure message.
      """
      @doc section: :mfa
      @spec delete_2fa(Conn.t(), any) :: Conn.t()
      def delete_2fa(conn, _params) do
        user = conn.assigns[:current_user]

        case Identity.disable_2fa(user) do
          :ok ->
            conn
            |> Controller.put_flash(:info, "Two-factor authentication disabled")
            |> Controller.redirect(to: Util.path_for(conn, :show_2fa))

          {:error, :not_found} ->
            conn
            |> Controller.put_flash(:error, "Unable to disable 2FA: login not found")
            |> Controller.redirect(to: Util.path_for(conn, :show_2fa))
        end
      end

      if Code.ensure_loaded?(EQRCode) do
        @spec encode_qr_code(String.t()) :: String.t()
        defp encode_qr_code(uri) do
          uri
          |> EQRCode.encode()
          |> EQRCode.svg(width: 250)
        end
      else
        @spec encode_qr_code(String.t()) :: String.t()
        defp encode_qr_code(_uri) do
          "<em>QR Code Unavailable</em>"
        end
      end
    else
      @doc "Render a form for enabling 2FA. Requires optional `NimbleTOTP` dependency."
      @doc section: :mfa
      @spec new_2fa(Conn.t(), any) :: no_return
      def new_2fa(_conn, _params), do: raise("NimbleTOTP is required for two-factor auth")

      @doc "Enable 2FA for the current user. Requires optional `NimbleTOTP` dependency."
      @doc section: :mfa
      @spec create_2fa(Conn.t(), Conn.params()) :: no_return
      def create_2fa(_conn, _params), do: raise("NimbleTOTP is required for two-factor auth")

      @doc "Disable 2FA for the current user. Requires optional `NimbleTOTP` dependency."
      @doc section: :mfa
      @spec delete_2fa(Conn.t(), Conn.params()) :: no_return
      def delete_2fa(_conn, _params), do: raise("NimbleTOTP is required for two-factor auth")
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
      Controller.render(conn, "new_password_token.html", error: nil)
    end

    @doc """
    Create and send a new password reset token for the user with the given `email`.

    This action uses the `c:Identity.Notifier.reset_password/2` callback to notify the user of the
    new token.

    ## Incoming Params

        %{
          "password_token" => %{
            "email" => string
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

      Controller.put_flash(
        conn,
        :info,
        "If your email is in our system, you will receive instructions to reset your password shortly."
      )
      |> Controller.redirect(to: "/")
    end

    @doc """
    Render a password change form with no active error message.

    ## Incoming Params

        %{
          "token" => string  # Password reset token, generally included as a URL param
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

      Controller.render(conn, "new_password.html",
        changeset: Identity.request_password_change(user)
      )
    end

    @doc """
    Create a new password using a password reset token.

    ## Incoming Params

        %{
          "token" => string,  # Password reset token, generally included as a URL param
          "password" => %{
            "password" => string,
            "password_confirmation" => string
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
    @spec create_password(Conn.t(), Conn.params()) :: Conn.t()
    def create_password(conn, %{"password" => password_params}) do
      user = conn.assigns[@assign_password_reset_user]

      case Identity.reset_password(user, password_params) do
        {:ok, _} ->
          conn
          |> Controller.put_flash(:info, "Password reset successfully.")
          |> Controller.redirect(to: Util.path_for(conn, :new_session))

        {:error, changeset} ->
          Controller.render(conn, "new_password.html", changeset: changeset)
      end
    end

    # Helper plug for password reset actions.
    @spec get_user_by_password_token(Conn.t(), any) :: Conn.t()
    defp get_user_by_password_token(conn, _opts) do
      %{"token" => token} = conn.params

      if user = Identity.get_user_by_password_token(token) do
        conn
        |> Conn.assign(@assign_password_reset_user, user)
        |> Conn.assign(:token, token)
      else
        conn
        |> Controller.put_flash(:error, "Reset password link is invalid or it has expired.")
        |> Controller.redirect(to: "/")
        |> Conn.halt()
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
      Controller.render(conn, "new_email.html", changeset: Identity.create_email_changeset())
    end

    @doc """
    Create a new email address for the current user and send a confirmation notification.

    ## Incoming Params

        %{
          "email" => %{
            "email" => string,
            "password" => string  # For verification
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
      fun = fn token -> Util.url_for(conn, :confirm_email, token) end

      case Identity.create_email_with_password(user, email, password, token_url: fun) do
        :ok ->
          conn
          |> Controller.put_flash(
            :info,
            "A link to confirm your email has been sent to the new address."
          )
          |> Controller.redirect(to: Util.path_for(conn, :new_email))

        {:error, changeset} ->
          Controller.render(conn, "new_email.html", changeset: changeset)
      end
    end

    @doc """
    Verify a newly registered email address using an email confirmation token.

    ## Incoming Params

        %{
          "token" => string  # Email confirmation token, generally included as a URL param
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
          |> Controller.put_flash(:info, "Email address confirmed")
          |> Controller.redirect(to: "/")

        {:error, _reason} ->
          conn
          |> Controller.put_flash(:error, "Email confirmation link is invalid or it has expired")
          |> Controller.redirect(to: "/")
      end
    end

    @doc """
    Delete an email address belonging to the current user.

    ## Incoming Params

        %{
          "email" => string
        }

    ## Success Response

    Redirects to `"/"` with an informational flash message.

    ## Error Response

    In the event of a deletion failure, redirects to `"/"` with an informational flash message.
    """
    @doc section: :email
    @spec delete_email(Conn.t(), Conn.params()) :: Conn.t()
    def delete_email(conn, %{"email" => email}) do
      user = conn.assigns[:current_user]

      case Identity.delete_email(user, email) do
        :ok ->
          conn
          |> Controller.put_flash(:info, "Email address removed successfully")
          |> Controller.redirect(to: "/")

        {:error, :only_email} ->
          conn
          |> Controller.put_flash(
            :error,
            "Unable to remove email address: accounts must have at least one valid email"
          )
          |> Controller.redirect(to: "/")

        {:error, :not_found} ->
          conn
          |> Controller.put_flash(:error, "Unable to remove email address: email not found")
          |> Controller.redirect(to: "/")
      end
    end

    #
    # User
    #

    @doc """
    Render form to create a new user with an email and password login.

    To add an email or password login to an existing user, use `new_email/2` and TODO.

    ## Incoming params

    This action has no incoming params.

    ## Render

    Renders `new_user.html` with the following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for creating a new user with an email and
        password login. Expects fields `email` and `password`.

    """
    @doc section: :user
    @spec new_user(Conn.t(), any) :: Conn.t()
    def new_user(conn, _params) do
      changeset = Identity.create_email_and_login_changeset()
      Controller.render(conn, "new_user.html", changeset: changeset)
    end

    @doc """
    Create a new user with an email and password login.

    ## Incoming Params

        %{
          "user" => %{
            "email" => string,
            "password" => string
          }
        }

    ## Success Response

    Logs in the new user with a flash message informing them to check their email for a
    confirmation link.

    ## Error Response

    In the event of an creation failure, renders `new_user.html` with the following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for creating a new user with an email and
        password login. Expects fields `email` and `password`.

    """
    @doc section: :user
    @spec create_user(Conn.t(), Conn.params()) :: Conn.t()
    def create_user(conn, %{"user" => user_params}) do
      fun = fn token -> Util.url_for(conn, :confirm_email, token) end

      case Identity.create_email_and_login(user_params, token_url: fun) do
        {:ok, user} ->
          conn
          |> Controller.put_flash(
            :info,
            "A link to confirm your email has been sent to your address."
          )
          |> Identity.Plug.log_in_and_redirect_user(user)

        {:error, changeset} ->
          Controller.render(conn, "new_user.html", changeset: changeset)
      end
    end

    #
    # Basic Login
    #

    @doc """
    Render a form to change the current user's password, using the current password as verification.

    ## Incoming params

    This action has no incoming params.

    ## Render

    Renders `edit_password.html` with the following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for updating a password login. Expects fields
        `password`, `password_confirmation`, and `current_password`.

    """
    @doc section: :login
    @spec edit_password(Conn.t(), any) :: Conn.t()
    def edit_password(conn, _params) do
      user = conn.assigns[:current_user]
      changeset = Identity.request_password_change(user)
      Controller.render(conn, "edit_password.html", changeset: changeset)
    end

    @doc """
    Update the current user's password, using the current password as verification.

    ## Incoming Params

        %{
          "password" => %{
            "current_password" => string,
            "password" => string,
            "password_confirmation" => string
          }
        }

    ## Success Response

    Updates the password, deletes all active sessions, and logs in the user while redirecting to
    the edit password form.

    ## Error Response

    In the event of an update failure, renders `edit_password.html` with the following assigns:

      * `:changeset` (`Ecto.Changeset`): Changeset for updating a password login. Expects fields
        `password`, `password_confirmation`, and `current_password`.

    """
    @doc section: :login
    @spec update_password(Conn.t(), Conn.params()) :: Conn.t()
    def update_password(conn, %{"password" => password_params}) do
      user = conn.assigns[:current_user]
      %{"current_password" => current_password} = password_params

      case Identity.update_password(user, current_password, password_params) do
        {:ok, user} ->
          conn
          |> Controller.put_flash(:info, "Password updated successfully.")
          |> Identity.Plug.log_in_and_redirect_user(user,
            to: Util.path_for(conn, :edit_password)
          )

        {:error, changeset} ->
          Controller.render(conn, "edit_password.html", changeset: changeset)
      end
    end

    #
    # OAuth
    #

    if Code.ensure_loaded?(Ueberauth) do
      @doc """
      Implements the request phase of the OAuth flow.

      This action is not supported and will always raise. Ueberauth should handle all request phase
      actions. If this action is called, it means that the relevant Ueberauth provider is not
      configured or requires manual implementation (such as the email/password strategy), which
      is not supported.
      """
      @doc section: :oauth
      @spec oauth_request(Conn.t(), Conn.params()) :: no_return
      def oauth_request(_conn, _params) do
        raise "OAuth request phase called for an unknown or unsupported provider"
      end

      @doc """
      Implements the callback phase of the OAuth flow.

      ## Incoming Params

      When an error has occurred, Ueberauth will place a failure struct in the `:ueberauth_failure`
      assign. Successful requests will have an `:ueberauth_auth` assign. There are no params
      expected.

      ## Success Response

        * If no user is currently logged in, and the authentication of an existing OAuth identity is
          successful, then the associated user is logged in and redirected.
        * If no user is currently logged in, and the authentication of a new OAuth identity is
          successful, then a new user is created and logged in.
        * If a user is logged in, and the authentication of a new OAuth identity is successful,
          then a new identity is added to the existing user.

      ## Error Response

        * If a user is logged in, and the authentication of an existing OAuth identity for a
          different user occurs, the user will be redirected with an error message.
        * If an issue occurs while saving an OAuth identity, the user is redirected with an
          error message.

      """
      @doc section: :oauth
      @spec oauth_callback(Conn.t(), Conn.params()) :: Conn.t()
      def oauth_callback(%{assigns: %{ueberauth_failure: failure}} = conn, _params) do
        Logger.warn("Error during OAuth callback: \n#{inspect(failure)}")
        message = Enum.map_join(failure.errors, "; ", fn error -> error.message end)

        conn
        |> Controller.put_flash(:error, "An error occurred during authentication: #{message}")
        |> Controller.redirect(to: "/")
      end

      def oauth_callback(%{assigns: %{current_user: nil, ueberauth_auth: auth}} = conn, _params) do
        case Identity.create_or_update_oauth(auth) do
          {:ok, user} ->
            conn
            |> Controller.put_flash(:info, "Successfully logged in")
            |> Identity.Plug.log_in_and_redirect_user(user)

          {:error, changeset} ->
            Logger.warn("Error during OAuth callback: \n#{inspect(changeset)}")

            conn
            |> put_flash(:error, "An error occurred while saving login")
            |> redirect(to: "/")
        end
      end

      def oauth_callback(%{assigns: %{current_user: user, ueberauth_auth: auth}} = conn, _params) do
        case Identity.create_or_update_oauth(auth, user: user) do
          {:ok, _user} ->
            conn
            |> Controller.put_flash(:info, "Successfully added new login")
            |> redirect(to: "/")

          {:error, :incorrect_user} ->
            conn
            |> Controller.put_flash(:error, "This login is already associated with another user")
            |> redirect(to: "/")

          {:error, changeset} ->
            Logger.warn("Error during OAuth callback: \n#{inspect(changeset)}")

            conn
            |> put_flash(:error, "An error occurred while saving login")
            |> redirect(to: "/")
        end
      end
    else
      @doc """
      Implements the request phase of the OAuth flow. Requires optional `Ueberauth` dependency.
      """
      @doc section: :oauth
      @spec oauth_request(Conn.t(), Conn.params()) :: no_return
      def oauth_request(_conn, _params) do
        raise "Ueberauth is required for OAuth support. Once installed, recompile with `mix deps.compile identity --force`."
      end

      @doc """
      Implements the callback phase of the OAuth flow. Requires optional `Ueberauth` dependency.
      """
      @doc section: :oauth
      @spec oauth_callback(Conn.t(), Conn.params()) :: no_return
      def oauth_callback(_conn, _params) do
        raise "Ueberauth is required for OAuth support. Once installed, recompile with `mix deps.compile identity --force`."
      end
    end
  end
end

if Code.ensure_loaded?(Plug.Conn) do
  defmodule Identity.Plug do
    @remember_me_default_name "_identity_user_remember_me"
    @remember_me_default_options [max_age: 5_184_000, same_site: "Lax", sign: true]

    @session_live_id :live_socket_id
    @session_pending :user_pending
    @session_return :user_return_to
    @session_token :user_token

    @moduledoc """
    Provides authentication helpers for Plug-based applications.

    ## Remember Me

    `log_in_user/3` optionally sets a "remember me" cookie to keep the user logged in after the
    end of the browser session. This cookie is called "#{@remember_me_default_name}" by default, but
    this can be configured using:

        config :identity, remember_me: [name: "_my_app_remember_me"]

    Additional options in the `:remember_me` configuration will be passed to the underlying
    function `Plug.Conn.put_resp_cookie/4` to configure the cookie. The following options are set
    by default:

    | Key | Default | Description |
    | `max_age` | `5_184_000` (60 days) | Time, in seconds, before the user is required to log in again. This setting also affects the expiration of persisted session records. |
    | `same_site` | `"Lax"` | Value of the [SameSite cookie attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite). |
    | `sign` | `true` | Whether to sign the cookie. See `Plug.Conn.put_resp_cookie/4` for more information. |

    ## Session Keys

    Identity uses the following session keys, which should not be modified by your application:

      * `:#{@session_live_id}`: Used to inform Phoenix LiveView when the user logs out. See
        `log_in_user/3` for more information.

      * `:#{@session_pending}`: Indicates whether a login is incomplete (for example, the user has
        passed password authentication but not 2-factor authentication). See `log_in_user/3` for
        more information.

      * `:#{@session_return}`: When an unauthenticated user is redirected to the login page, this key
        stores the original destination so that the user can return there after login.

      * `:#{@session_token}`: Session token, used for user lookup.

    """
    alias Plug.Conn

    #
    # Session Management
    #

    @doc """
    Log in the given `user` to a new session.

    This function does not redirect after setting up the session. To follow the post-login
    destination stored in the connection, or to manually send the user to a different route after
    login, see `log_in_and_redirect_user/3`.

    ## Options

      * `:client` (string): Name of the client logging in. Defaults to the browser/OS indicated by
        the `User-Agent` header and parsed by `UAParser`.

      * `:pending` (boolean): Whether the login is pending, meaning the user has been identified
        but not fully authenticated. Useful in 2-factor login flows. Defaults to `false`.

      * `:remember_me` (boolean): Whether to set a "remember me" cookie to persist logins beyond the
        current browser session. Defaults to `false`.

    ## Session Renewal

    This function renews the session ID and clears the entire session to avoid fixation attacks. If
    there is session data that should be preserved after log in (and log out), then it is necessary
    to fetch and reset the data:

        my_session_data = get_session(conn, :my_session_data)

        conn
        |> log_in_user(user, params)
        |> put_session(:my_session_data, my_session_data)

    If using Phoenix LiveView, this function also sets a `:#{@session_live_id}` key in the session. You
    may use this to automatically disconnect LiveView sessions when a user logs out:

        if live_socket_id = get_session(conn, :#{@session_live_id}) do
          MyAppWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
        end

        conn
        |> log_out_user()

    If not using Phoenix LiveView, this session value can be ignored.
    """
    @spec log_in_user(Conn.t(), Identity.User.t(), keyword) :: Conn.t()
    def log_in_user(conn, user, opts \\ []) do
      client = opts[:client] || extract_client_name(conn)
      token = Identity.create_session(user, client)

      conn
      |> renew_session()
      |> Conn.put_session(@session_token, token)
      |> Conn.put_session(@session_pending, opts[:pending] == true)
      |> Conn.put_session(@session_live_id, "identity_sessions:#{Base.url_encode64(token)}")
      |> maybe_write_remember_me_cookie(token, opts[:remember_me])
    end

    @doc """
    Log in the given `user` to a new session and redirect to another route.

    ## Options

    In addition to the options offered by `log_in_user/3`, this function also accepts:

      * `:to` (string): Path to send newly authenticated users if they don't have a destination
        stored in the session. Defaults to `"/"`.

    """
    @spec log_in_and_redirect_user(Conn.t(), Identity.User.t(), keyword) :: Conn.t()
    def log_in_and_redirect_user(conn, user, opts \\ []) do
      user_return_to = Conn.get_session(conn, @session_return) || opts[:to] || "/"

      conn
      |> log_in_user(user, opts)
      |> Conn.resp(:found, "")
      |> Conn.put_resp_header("location", user_return_to)
    end

    @spec extract_client_name(Conn.t()) :: String.t()
    defp extract_client_name(conn) do
      Conn.get_req_header(conn, "user-agent")
      |> List.first("")
      |> UAParser.parse()
      |> to_string()
    end

    @spec renew_session(Conn.t()) :: Conn.t()
    defp renew_session(conn) do
      user_return_to = Conn.get_session(conn, @session_return)

      conn
      |> Conn.configure_session(renew: true)
      |> Conn.clear_session()
      |> Conn.put_session(@session_return, user_return_to)
    end

    @doc """
    Log out the current user from their session.

    Similar to `log_in_user/3`, this function clears and renews the session. See `log_in_user/3` for
    an example of preserving data during session renewal.

    ## Options

      * `:to` (string): Path to send newly logged-out users. Defaults to `"/"`.

    """
    @spec log_out_user(Conn.t()) :: Conn.t()
    def log_out_user(conn, opts \\ []) do
      user_token = Conn.get_session(conn, @session_token)
      user_token && Identity.delete_session(user_token)

      conn
      |> renew_session()
      |> Conn.delete_resp_cookie(remember_me_cookie_name())
      |> Conn.resp(:found, "")
      |> Conn.put_resp_header("location", opts[:to] || "/")
    end

    #
    # Plugs
    #

    @doc "Authenticates the user by looking into the session and remember me token."
    @spec fetch_current_user(Plug.Conn.t(), any) :: Plug.Conn.t()
    def fetch_current_user(conn, _opts) do
      {user_token, conn} = ensure_user_token(conn)
      user = user_token && Identity.get_user_by_session(user_token)

      Conn.assign(conn, :current_user, user)
    end

    @spec ensure_user_token(Plug.Conn.t()) :: {String.t() | nil, Plug.Conn.t()}
    defp ensure_user_token(conn) do
      if user_token = Conn.get_session(conn, @session_token) do
        {user_token, conn}
      else
        conn = Conn.fetch_cookies(conn, signed: [remember_me_cookie_name()])

        if user_token = conn.cookies[remember_me_cookie_name()] do
          {user_token, Conn.put_session(conn, @session_token, user_token)}
        else
          {nil, conn}
        end
      end
    end

    @doc """
    Require that a user is **not** logged in, and redirect otherwise.

    Does not redirect if the user's login is pending. See `log_in_user/3` for more information.

    ## Options

      * `:to`: Destination to redirect authenticated users. Defaults to `"/"`.

    ## Examples

        # Defaults to configured `:after_sign_in` path or `"/"`.
        plug :redirect_if_user_is_authenticated

        # Optionally set the redirect destination here.
        plug :redirect_if_user_is_authenticated, to: "/"

    """
    @spec redirect_if_user_is_authenticated(Conn.t(), keyword) :: Conn.t()
    def redirect_if_user_is_authenticated(conn, opts) do
      pending? = Conn.get_session(conn, @session_pending) == true

      if conn.assigns[:current_user] && !pending? do
        conn
        |> Conn.resp(:found, "")
        |> Conn.put_resp_header("location", opts[:to] || "/")
        |> Conn.halt()
      else
        conn
      end
    end

    @doc """
    Require that a user is logged in, and redirect otherwise.

    Also redirects if the user's login is pending. See `log_in_user/3` for more information.

    ## Options

      * `:message` (string): Flash error message to display for redirected users. Defaults to
        "You must log in to access this page." Ignored if `Phoenix.Controller` is not available.

      * `:to` (string): Destination to redirect unauthenticated users. Defaults to `"/"`.

    ## Examples

        # Defaults to configured `:sign_in` path or `"/"`.
        plug :require_authenticated_user, message: "

        # Optionally set the redirect destination here.
        plug :require_authenticated_user, to: "/"

    """
    @spec require_authenticated_user(Conn.t(), keyword) :: Conn.t()
    def require_authenticated_user(conn, opts) do
      pending? = Conn.get_session(conn, @session_pending) == true

      if conn.assigns[:current_user] && !pending? do
        conn
      else
        conn
        |> maybe_put_log_in_flash(opts[:message])
        |> maybe_store_return_to()
        |> Conn.resp(:found, "")
        |> Conn.put_resp_header("location", opts[:to] || "/")
        |> Conn.halt()
      end
    end

    @spec maybe_put_log_in_flash(Conn.t(), String.t() | nil) :: Conn.t()
    if Code.ensure_loaded?(Phoenix.Controller) do
      defp maybe_put_log_in_flash(conn, message) do
        Phoenix.Controller.put_flash(
          conn,
          :error,
          message || "You must log in to access this page."
        )
      end
    else
      defp maybe_put_log_in_flash(conn, _message), do: conn
    end

    @spec maybe_store_return_to(Conn.t()) :: Conn.t()
    defp maybe_store_return_to(%{method: "GET"} = conn) do
      Conn.put_session(conn, @session_return, current_path(conn))
    end

    defp maybe_store_return_to(conn), do: conn

    @doc """
    Require that the user has been identified, but login is incomplete.

    See `log_in_user/3` for more information.

    ## Options

      * `:message` (string): Flash error message to display for redirected users. Defaults to
        "You must log in to access this page." Ignored if `Phoenix.Controller` is not available.

      * `:to` (string): Destination to redirect unauthenticated or fully authenticated users.
        Defaults to `"/"`.

    """
    @spec require_pending_login(Conn.t(), keyword) :: Conn.t()
    def require_pending_login(conn, opts) do
      pending? = Conn.get_session(conn, @session_pending) == true

      if pending? do
        conn
      else
        conn
        |> maybe_put_log_in_flash(opts[:message])
        |> maybe_store_return_to()
        |> Conn.resp(:found, "")
        |> Conn.put_resp_header("location", opts[:to] || "/")
        |> Conn.halt()
      end
    end

    #
    # Cookie Helpers
    #

    @spec maybe_write_remember_me_cookie(Conn.t(), String.t(), Conn.params()) :: Conn.t()
    defp maybe_write_remember_me_cookie(conn, token, true) do
      Conn.put_resp_cookie(conn, remember_me_cookie_name(), token, remember_me_cookie_options())
    end

    defp maybe_write_remember_me_cookie(conn, _token, _params) do
      conn
    end

    defp remember_me_cookie_name do
      Application.get_env(:identity, :remember_me)[:name] || @remember_me_default_name
    end

    defp remember_me_cookie_options do
      config = Application.get_env(:identity, :remember_me) || []

      Keyword.merge(
        @remember_me_default_options,
        Keyword.delete(config, :name)
      )
    end

    #
    # Path Helpers
    #

    # Taken from https://github.com/phoenixframework/phoenix/blob/a2e4b1a/lib/phoenix/controller.ex#L1466
    @spec current_path(Conn.t()) :: String.t()
    defp current_path(%Conn{query_string: ""} = conn) do
      normalized_request_path(conn)
    end

    defp current_path(%Conn{query_string: query_string} = conn) do
      normalized_request_path(conn) <> "?" <> query_string
    end

    @spec normalized_request_path(Conn.t()) :: String.t()
    defp normalized_request_path(%{path_info: info, script_name: script}) do
      "/" <> Enum.join(script ++ info, "/")
    end
  end
end

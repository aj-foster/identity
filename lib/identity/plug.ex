defmodule Identity.Plug do
  @moduledoc """
  Provides authentication helpers for Plug-based applications.

  ## Session Keys

  Identity uses the following session keys, which should not be modified by your application:

    * `:live_socket_id`: Used to inform Phoenix LiveView when the user logs out. See `log_in_user/3`
      for more information.

    * `:user_return_to`: When an unauthenticated user is redirected to the login page, this key
      stores the original destination so that the user can return there after login.

    * `:user_token`: Session token, used for user lookup.

  """
  alias Plug.Conn

  @remember_me_cookie_name Application.compile_env(:identity, :remember_me)[:name] ||
                             "_identity_user_remember_me"
  @remember_me_default_options [max_age: 5_184_000, same_site: "Lax", sign: true]
  @remember_me_configuration Application.compile_env(:identity, :remember_me) || []
  @remember_me_options Keyword.merge(
                         @remember_me_default_options,
                         Keyword.delete(@remember_me_configuration, :name)
                       )

  #
  # Configured Paths
  #

  @sign_in_path Application.compile_env(:identity, :paths)[:sign_in] || "/"
  @after_sign_in_path Application.compile_env(:identity, :paths)[:after_sign_in] || "/"
  @after_sign_out_path Application.compile_env(:identity, :paths)[:after_sign_out] || "/"

  #
  # Session Management
  #

  @doc """
  Log in the given `user` to a new session.

  ## Options

    * `:client` (string): Name of the client logging in. Defaults to the browser/OS indicated by the
      `User-Agent` header and parsed by `UAParser`.

    * `:remember_me` (boolean): Whether to set a "remember me" cookie to persist logins beyond the
      current browser session.

  ## Session Renewal

  This function renews the session ID and clears the entire session to avoid fixation attacks. If
  there is session data that should be preseved after log in (and log out), then it is necessary to
  fetch and reset the data:

      my_session_data = get_session(conn, :my_session_data)

      conn
      |> log_in_user(user, params)
      |> put_session(:my_session_data, my_session_data)

  If using Phoenix LiveView, this function also sets a `:live_socket_id` key in the session. You
  may use this to automatically disconnect LiveView sessions when a user logs out:

      if live_socket_id = get_session(conn, :live_socket_id) do
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
    user_return_to = Conn.get_session(conn, :user_return_to)

    conn
    |> renew_session()
    |> Conn.put_session(:user_token, token)
    |> Conn.put_session(:live_socket_id, "identity_sessions:#{Base.url_encode64(token)}")
    |> maybe_write_remember_me_cookie(token, opts[:remember_me])
    |> Conn.resp(:found, "")
    |> Conn.put_resp_header("location", user_return_to || @after_sign_in_path)
  end

  @spec extract_client_name(Conn.t()) :: String.t()
  defp extract_client_name(conn) do
    Conn.get_req_header(conn, "user-agent")
    |> List.first("")
    |> UAParser.parse()
    |> to_string()
  end

  @spec maybe_write_remember_me_cookie(Conn.t(), String.t(), Conn.params()) :: Conn.t()
  defp maybe_write_remember_me_cookie(conn, token, true) do
    Conn.put_resp_cookie(conn, @remember_me_cookie_name, token, @remember_me_options)
  end

  defp maybe_write_remember_me_cookie(conn, _token, _params) do
    conn
  end

  @spec renew_session(Conn.t()) :: Conn.t()
  defp renew_session(conn) do
    conn
    |> Conn.configure_session(renew: true)
    |> Conn.clear_session()
  end

  @doc """
  Log out the current user from their session.

  Similar to `log_in_user/3`, this function clears and renews the session. See `log_in_user/3` for
  an example of preserving data during session renewal.
  """
  @spec log_out_user(Conn.t()) :: Conn.t()
  def log_out_user(conn) do
    user_token = Conn.get_session(conn, :user_token)
    user_token && Identity.delete_session(user_token)

    conn
    |> renew_session()
    |> Conn.delete_resp_cookie(@remember_me_cookie_name)
    |> Conn.resp(:found, "")
    |> Conn.put_resp_header("location", @after_sign_out_path)
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
    if user_token = Conn.get_session(conn, :user_token) do
      {user_token, conn}
    else
      conn = Conn.fetch_cookies(conn, signed: [@remember_me_cookie_name])

      if user_token = conn.cookies[@remember_me_cookie_name] do
        {user_token, Conn.put_session(conn, :user_token, user_token)}
      else
        {nil, conn}
      end
    end
  end

  @doc """
  Require that a user is **not** logged in.

  ## Options

    * `:to`: Destination to redirect authenticated users. Defaults to the configured
      `:after_sign_in` path.

  ## Examples

      # Defaults to configured `:after_sign_in` path or `"/"`.
      plug :redirect_if_user_is_authenticated

      # Optionally set the redirect destination here.
      plug :redirect_if_user_is_authenticated, to: "/"

  """
  @spec redirect_if_user_is_authenticated(Conn.t(), keyword) :: Conn.t()
  def redirect_if_user_is_authenticated(conn, opts) do
    if conn.assigns[:current_user] do
      conn
      |> Conn.resp(:found, "")
      |> Conn.put_resp_header("location", opts[:to] || @after_sign_in_path)
      |> Conn.halt()
    else
      conn
    end
  end

  @doc """
  Require that a user is logged in.

  ## Options

    * `:message` (string): Flash error message to display for redirected users. Defaults to
      "You must log in to access this page." Ignored if `Phoenix.Controller` is not available.

    * `:to` (string): Destination to redirect unauthenticated users. Defaults to the configured
      `:sign_in` path or `"/"`.

  ## Examples

      # Defaults to configured `:sign_in` path or `"/"`.
      plug :require_authenticated_user, message: "

      # Optionally set the redirect destination here.
      plug :require_authenticated_user, to: "/"

  """
  @spec require_authenticated_user(Conn.t(), keyword) :: Conn.t()
  def require_authenticated_user(conn, opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> maybe_put_log_in_flash(opts[:message])
      |> maybe_store_return_to()
      |> Conn.resp(:found, "")
      |> Conn.put_resp_header("location", opts[:to] || @sign_in_path)
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
    Conn.put_session(conn, :user_return_to, current_path(conn))
  end

  defp maybe_store_return_to(conn), do: conn

  #
  # Path Helpers
  #

  # Taken from https://github.com/phoenixframework/phoenix/blob/a2e4b1a/lib/phoenix/controller.ex#L1466
  @spec current_path(Conn.t()) :: String.t()
  defp current_path(%Plug.Conn{query_string: ""} = conn) do
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

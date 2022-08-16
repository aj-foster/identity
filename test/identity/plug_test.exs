defmodule Identity.PlugTest do
  use Identity.ConnCase, async: true

  @remember_me_cookie "_identity_user_remember_me"

  describe "log_in_user/3" do
    test "stores the user token in the session", %{conn: conn, user: user} do
      conn = Identity.Plug.log_in_user(conn, user)
      assert token = get_session(conn, :user_token)
      assert get_session(conn, :live_socket_id) == "identity_sessions:#{Base.url_encode64(token)}"
      assert Identity.get_user_by_session(token)
    end

    test "clears everything previously stored in the session", %{conn: conn, user: user} do
      conn = conn |> put_session(:to_be_removed, "value") |> Identity.Plug.log_in_user(user)
      refute get_session(conn, :to_be_removed)
    end

    test "optionally writes a remember me cookie", %{conn: conn, user: user} do
      conn = conn |> fetch_cookies() |> Identity.Plug.log_in_user(user, remember_me: true)
      assert get_session(conn, :user_token) == conn.cookies[@remember_me_cookie]
      assert %{value: signed_token, max_age: max_age} = conn.resp_cookies[@remember_me_cookie]
      assert signed_token != get_session(conn, :user_token)
      assert max_age == 5_184_000
    end

    test "optionally marks login as pending", %{conn: conn, user: user} do
      conn = Identity.Plug.log_in_user(conn, user, pending: true)
      assert get_session(conn, :user_token)
      assert get_session(conn, :user_pending) == true
    end
  end

  describe "log_in_and_redirect_user/3" do
    test "stores the user token in the session", %{conn: conn, user: user} do
      conn = Identity.Plug.log_in_and_redirect_user(conn, user)
      assert token = get_session(conn, :user_token)
      assert get_session(conn, :live_socket_id) == "identity_sessions:#{Base.url_encode64(token)}"
      assert redirected_to(conn) == "/"
      assert Identity.get_user_by_session(token)
    end

    test "clears everything previously stored in the session", %{conn: conn, user: user} do
      conn =
        conn
        |> put_session(:to_be_removed, "value")
        |> Identity.Plug.log_in_and_redirect_user(user)

      refute get_session(conn, :to_be_removed)
    end

    test "redirects to the configured path", %{conn: conn, user: user} do
      conn =
        conn
        |> put_session(:user_return_to, "/hello")
        |> Identity.Plug.log_in_and_redirect_user(user)

      assert redirected_to(conn) == "/hello"
      refute get_session(conn, :user_return_to)
    end

    test "optionally writes a remember me cookie", %{conn: conn, user: user} do
      conn =
        conn |> fetch_cookies() |> Identity.Plug.log_in_and_redirect_user(user, remember_me: true)

      assert get_session(conn, :user_token) == conn.cookies[@remember_me_cookie]
      assert %{value: signed_token, max_age: max_age} = conn.resp_cookies[@remember_me_cookie]
      assert signed_token != get_session(conn, :user_token)
      assert max_age == 5_184_000
    end

    test "optionally marks login as pending", %{conn: conn, user: user} do
      conn = Identity.Plug.log_in_and_redirect_user(conn, user, pending: true)
      assert get_session(conn, :user_pending) == true
      assert redirected_to(conn) == "/"
    end
  end

  describe "log_out_user/1" do
    test "erases session and cookies", %{conn: conn, user: user} do
      user_token = Identity.create_session(user, "Test")

      conn =
        conn
        |> put_session(:user_token, user_token)
        |> put_req_cookie(@remember_me_cookie, user_token)
        |> fetch_cookies()
        |> Identity.Plug.log_out_user()

      refute get_session(conn, :user_token)
      refute conn.cookies[@remember_me_cookie]
      assert %{max_age: 0} = conn.resp_cookies[@remember_me_cookie]
      assert redirected_to(conn) == "/"
      refute Identity.get_user_by_session(user_token)
    end

    test "works even if user is already logged out", %{conn: conn} do
      conn = conn |> fetch_cookies() |> Identity.Plug.log_out_user()
      refute get_session(conn, :user_token)
      assert %{max_age: 0} = conn.resp_cookies[@remember_me_cookie]
      assert redirected_to(conn) == "/"
    end
  end

  describe "fetch_identity/2" do
    test "authenticates user from session", %{conn: conn, user: user} do
      user_token = Identity.create_session(user, "Test")
      conn = conn |> put_session(:user_token, user_token) |> Identity.Plug.fetch_identity([])
      assert conn.assigns.current_user.id == user.id
    end

    test "authenticates user from cookies", %{conn: conn, user: user} do
      logged_in_conn =
        conn
        |> fetch_cookies()
        |> Identity.Plug.log_in_user(user, remember_me: true)

      user_token = logged_in_conn.cookies[@remember_me_cookie]
      %{value: signed_token} = logged_in_conn.resp_cookies[@remember_me_cookie]

      conn =
        conn
        |> put_req_cookie(@remember_me_cookie, signed_token)
        |> Identity.Plug.fetch_identity([])

      assert get_session(conn, :user_token) == user_token
      assert conn.assigns.current_user.id == user.id
    end

    test "does not authenticate if data is missing", %{conn: conn, user: user} do
      _ = Identity.create_session(user, "Test")
      conn = Identity.Plug.fetch_identity(conn, [])
      refute get_session(conn, :user_token)
      refute conn.assigns.current_user
    end
  end

  describe "redirect_if_authenticated/2" do
    test "redirects if user is authenticated", %{conn: conn, user: user} do
      conn =
        conn
        |> assign(:current_user, user)
        |> Identity.Plug.redirect_if_authenticated([])

      assert conn.halted
      assert redirected_to(conn) == "/"
    end

    test "does not redirect if user is not authenticated", %{conn: conn} do
      conn = Identity.Plug.redirect_if_authenticated(conn, [])
      refute conn.halted
      refute conn.status
    end

    test "does not redirect if the login is pending", %{conn: conn, user: user} do
      conn =
        conn
        |> assign(:current_user, user)
        |> put_session(:user_pending, true)
        |> Identity.Plug.redirect_if_authenticated([])

      refute conn.halted
      refute conn.status
    end
  end

  describe "redirect_if_unauthenticated/2" do
    test "redirects if user is not authenticated", %{conn: conn} do
      conn = conn |> fetch_flash() |> Identity.Plug.redirect_if_unauthenticated([])
      assert conn.halted
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) == "You must log in to access this page."
    end

    test "stores the path to redirect to on GET", %{conn: conn} do
      halted_conn =
        %{conn | path_info: ["foo"], query_string: ""}
        |> fetch_flash()
        |> Identity.Plug.redirect_if_unauthenticated([])

      assert halted_conn.halted
      assert get_session(halted_conn, :user_return_to) == "/foo"

      halted_conn =
        %{conn | path_info: ["foo"], query_string: "bar=baz"}
        |> fetch_flash()
        |> Identity.Plug.redirect_if_unauthenticated([])

      assert halted_conn.halted
      assert get_session(halted_conn, :user_return_to) == "/foo?bar=baz"

      halted_conn =
        %{conn | path_info: ["foo"], query_string: "bar", method: "POST"}
        |> fetch_flash()
        |> Identity.Plug.redirect_if_unauthenticated([])

      assert halted_conn.halted
      refute get_session(halted_conn, :user_return_to)
    end

    test "uses configured message", %{conn: conn} do
      conn =
        conn
        |> fetch_flash()
        |> Identity.Plug.redirect_if_unauthenticated(message: "Custom message")

      assert get_flash(conn, :error) == "Custom message"
    end

    test "does not redirect if user is authenticated", %{conn: conn, user: user} do
      conn =
        conn
        |> assign(:current_user, user)
        |> Identity.Plug.redirect_if_unauthenticated([])

      refute conn.halted
      refute conn.status
    end

    test "redirects if the login is pending", %{conn: conn, user: user} do
      conn =
        conn
        |> fetch_flash()
        |> assign(:current_user, user)
        |> put_session(:user_pending, true)
        |> Identity.Plug.redirect_if_unauthenticated([])

      assert conn.halted
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) == "You must log in to access this page."
    end
  end

  describe "require_pending_login/2" do
    test "redirects if user is not authenticated", %{conn: conn} do
      conn = conn |> fetch_flash() |> Identity.Plug.require_pending_login([])
      assert conn.halted
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) == "You must log in to access this page."
    end

    test "redirects if the login is not pending", %{conn: conn, user: user} do
      conn =
        conn
        |> fetch_flash()
        |> Identity.Plug.log_in_user(user)
        |> Identity.Plug.require_pending_login([])

      assert conn.halted
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) == "You must log in to access this page."
    end

    test "stores the path to redirect to on GET", %{conn: conn} do
      halted_conn =
        %{conn | path_info: ["foo"], query_string: ""}
        |> fetch_flash()
        |> Identity.Plug.require_pending_login([])

      assert halted_conn.halted
      assert get_session(halted_conn, :user_return_to) == "/foo"

      halted_conn =
        %{conn | path_info: ["foo"], query_string: "bar=baz"}
        |> fetch_flash()
        |> Identity.Plug.require_pending_login([])

      assert halted_conn.halted
      assert get_session(halted_conn, :user_return_to) == "/foo?bar=baz"

      halted_conn =
        %{conn | path_info: ["foo"], query_string: "bar", method: "POST"}
        |> fetch_flash()
        |> Identity.Plug.require_pending_login([])

      assert halted_conn.halted
      refute get_session(halted_conn, :user_return_to)
    end

    test "uses configured message", %{conn: conn} do
      conn =
        conn
        |> fetch_flash()
        |> Identity.Plug.require_pending_login(message: "Custom message")

      assert get_flash(conn, :error) == "Custom message"
    end

    test "does not redirect if the login is pending", %{conn: conn, user: user} do
      conn =
        conn
        |> assign(:current_user, user)
        |> put_session(:user_pending, true)
        |> Identity.Plug.require_pending_login([])

      refute conn.halted
      refute conn.status
    end
  end
end

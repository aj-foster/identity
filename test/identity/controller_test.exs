defmodule Identity.ControllerTest do
  use Identity.ConnCase

  describe "new_session/2" do
    test "renders login form", %{conn: conn} do
      conn = get(conn, "/session/new")
      assert html_response(conn, 200) =~ "form action=\"/session/new\""
    end
  end

  describe "create_session/2" do
    setup do
      user = Factory.insert(:user)
      password = Factory.valid_user_password()
      Factory.insert(:basic_login, password: password, user: user)
      %{email: email} = Factory.insert(:email, user: user)

      %{email: email, password: password, user: user}
    end

    test "rejects unknown user", %{conn: conn} do
      params = %{"session" => %{"email" => "unknown@example.com", "password" => "wrong"}}
      conn = post(conn, "/session/new", params)
      assert html_response(conn, 200) =~ "Invalid e-mail or password"
    end

    test "rejects incorrect password", %{conn: conn, email: email} do
      params = %{"session" => %{"email" => email, "password" => "wrong"}}
      conn = post(conn, "/session/new", params)
      assert html_response(conn, 200) =~ "Invalid e-mail or password"
    end

    test "redirects to default post-login path if successful", %{
      conn: conn,
      email: email,
      password: password,
      user: %{id: user_id}
    } do
      params = %{"session" => %{"email" => email, "password" => password}}
      conn = post(conn, "/session/new", params)
      assert redirected_to(conn) == "/"

      token = get_session(conn, :user_token)
      assert %Identity.User{id: ^user_id} = Identity.get_user_by_session(token)
    end

    test "redirects to stored post-login path if successful", %{
      conn: conn,
      email: email,
      password: password
    } do
      params = %{"session" => %{"email" => email, "password" => password}}

      conn =
        conn
        |> put_session(:user_return_to, "/test")
        |> post("/session/new", params)

      assert redirected_to(conn) == "/test"
    end

    test "optionally stores remember me cookie", %{conn: conn, email: email, password: password} do
      params = %{
        "session" => %{"email" => email, "password" => password, "remember_me" => "true"}
      }

      conn = post(conn, "/session/new", params)
      assert conn.resp_cookies["_identity_user_remember_me"]
    end

    test "redirects to 2FA route if enabled", %{
      conn: conn,
      email: email,
      password: password,
      user: user
    } do
      changeset = Identity.request_enable_2fa(user)
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)
      Identity.enable_2fa(changeset, otp)

      params = %{"session" => %{"email" => email, "password" => password}}
      conn = post(conn, "/session/new", params)

      assert redirected_to(conn) == "/session/2fa"
      assert get_session(conn, :session_2fa_pending)
      refute conn.resp_cookies["_identity_user_remember_me"]
    end
  end
end

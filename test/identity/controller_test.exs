defmodule Identity.ControllerTest do
  use Identity.ConnCase, async: true

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

      params = %{
        "session" => %{"email" => email, "password" => password, "remember_me" => "true"}
      }

      conn = post(conn, "/session/new", params)

      assert redirected_to(conn) == "/session/2fa"
      assert get_session(conn, :user_pending)
      refute conn.resp_cookies["_identity_user_remember_me"]
    end
  end

  describe "new_2fa/2" do
    test "renders 2FA form", %{conn: conn} do
      user = Factory.insert(:user)

      conn =
        conn
        |> Identity.Plug.log_in_user(user, pending: true)
        |> get("/session/2fa")

      assert html_response(conn, 200) =~ "form action=\"/session/2fa\""
    end
  end

  describe "validate_2fa/2" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)

      %{user: user}
    end

    test "accepts a valid 2FA code", %{conn: conn, user: user} do
      changeset = Identity.request_enable_2fa(user)
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)
      Identity.enable_2fa(changeset, otp)

      params = %{"session" => %{"code" => otp}}

      conn =
        conn
        |> Identity.Plug.log_in_user(user, pending: true)
        |> put_session(:session_remember_me_pending, true)
        |> post("/session/2fa", params)

      assert redirected_to(conn) == "/"
      refute get_session(conn, :user_pending)
      assert conn.resp_cookies["_identity_user_remember_me"]
    end

    test "rejects an invalid 2FA code", %{conn: conn, user: user} do
      changeset = Identity.request_enable_2fa(user)
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)
      Identity.enable_2fa(changeset, otp)

      params = %{"session" => %{"code" => "000000"}}

      conn =
        conn
        |> Identity.Plug.log_in_user(user, pending: true)
        |> put_session(:session_remember_me_pending, true)
        |> post("/session/2fa", params)

      assert html_response(conn, 200) =~ "form action=\"/session/2fa\""
      assert get_session(conn, :user_pending)
      refute conn.resp_cookies["_identity_user_remember_me"]
    end
  end

  describe "new_password_token/2" do
    test "renders the reset password page", %{conn: conn} do
      conn = get(conn, "/password/new")
      response = html_response(conn, 200)
      assert response =~ "form action=\"/password/new\""
    end
  end

  describe "create_password_token/2" do
    test "sends a new reset password token", %{conn: conn, user: user} do
      %{email: email} = Factory.insert(:email, user: user)
      conn = post(conn, "/password/new", %{"password_token" => %{"email" => email}})

      assert redirected_to(conn) == "/"
      assert get_flash(conn, :info) =~ "If your email is in our system"
      assert Repo.get_by!(Identity.Schema.PasswordToken, user_id: user.id)
    end

    test "does not send reset password token if email is invalid", %{conn: conn} do
      conn =
        post(conn, "/password/new", %{"password_token" => %{"email" => "unknown@example.com"}})

      assert redirected_to(conn) == "/"
      assert get_flash(conn, :info) =~ "If your email is in our system"
      assert Repo.all(Identity.Schema.PasswordToken) == []
    end
  end

  describe "new_password/2" do
    test "renders reset password", %{conn: conn, user: user} do
      Factory.insert(:basic_login, user: user)
      {:ok, %{token: token}} = Identity.request_password_reset(user)

      conn = get(conn, "/password/#{token}")
      assert html_response(conn, 200) =~ "form action=\"/password/#{token}\""
    end

    test "does not render reset password with invalid token", %{conn: conn} do
      conn = get(conn, "/password/faketoken")
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) =~ "Reset password link is invalid or it has expired"
    end
  end

  describe "update_password/2" do
    setup %{user: user} do
      {:ok, %{token: encoded_token}} = Identity.request_password_reset(user)
      %{token: encoded_token}
    end

    test "resets password once", %{conn: conn, user: user, token: token} do
      %{email: email} = Factory.insert(:email, user: user)
      Factory.insert(:basic_login, user: user)

      conn =
        put(conn, "/password/#{token}", %{
          "password" => %{
            "password" => "new valid password",
            "password_confirmation" => "new valid password"
          }
        })

      assert redirected_to(conn) == "/session/new"
      refute get_session(conn, :user_token)
      assert get_flash(conn, :info) =~ "Password reset successfully"
      assert Identity.get_user_by_email_and_password(email, "new valid password")
    end

    test "does not reset password on invalid data", %{conn: conn, user: user, token: token} do
      Factory.insert(:basic_login, user: user)

      conn =
        put(conn, "/password/#{token}", %{
          "password" => %{
            "password" => "too short",
            "password_confirmation" => "does not match"
          }
        })

      response = html_response(conn, 200)
      assert response =~ "form action=\"/password/#{token}\""
      assert response =~ "should be at least 12 character(s)"
      assert response =~ "does not match password"
    end

    test "does not reset password with invalid token", %{conn: conn} do
      conn = put(conn, "/password/faketoken")
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) =~ "Reset password link is invalid or it has expired"
    end
  end
end

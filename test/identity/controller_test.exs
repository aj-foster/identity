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

  describe "delete_session/2" do
    test "logs out a logged-in user", %{conn: conn, user: user} do
      conn =
        conn
        |> Identity.Plug.log_in_user(user)
        |> delete("/session")

      refute get_session(conn, :user_token)
      assert redirected_to(conn) == "/"
    end

    test "ignores a logged out user", %{conn: conn} do
      conn = delete(conn, "/session")

      refute get_session(conn, :user_token)
      assert redirected_to(conn) == "/"
    end
  end

  describe "pending_2fa/2" do
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
      :ok = Identity.request_password_reset(user)
      assert_received {:reset_password, ^user, token}

      conn = get(conn, "/password/#{token}")
      assert html_response(conn, 200) =~ "form action=\"/password/#{token}\""
    end

    test "does not render reset password with invalid token", %{conn: conn} do
      conn = get(conn, "/password/faketoken")
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) =~ "Reset password link is invalid or it has expired"
    end
  end

  describe "create_password/2" do
    setup %{user: user} do
      :ok = Identity.request_password_reset(user)
      assert_received {:reset_password, ^user, encoded_token}
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

  describe "new_email/2" do
    test "renders the new email page", %{conn: conn, user: user} do
      conn = Identity.Plug.log_in_user(conn, user)
      conn = get(conn, "/email/new")
      response = html_response(conn, 200)
      assert response =~ "form action=\"/email/new\""
    end

    test "redirects if user is not logged in", %{conn: conn} do
      conn = get(conn, "/email/new")
      assert redirected_to(conn) == "/"
    end
  end

  describe "create_email/2" do
    setup %{user: user} do
      password = Factory.valid_user_password()
      Factory.insert(:basic_login, password: password, user: user)

      %{password: password}
    end

    test "adds a new email address", %{conn: conn, password: password, user: user} do
      params = %{"email" => %{"email" => "new@example.com", "password" => password}}
      conn = Identity.Plug.log_in_user(conn, user)
      conn = post(conn, "/email/new", params)

      assert redirected_to(conn) == "/email/new"
      assert get_flash(conn, :info) =~ "A link to confirm"
      assert Identity.get_user_by_email("new@example.com")
    end

    test "does not update email on invalid password", %{conn: conn, user: user} do
      params = %{"email" => %{"email" => "new@example.com", "password" => "wrong"}}
      conn = Identity.Plug.log_in_user(conn, user)
      conn = post(conn, "/email/new", params)

      response = html_response(conn, 200)
      assert response =~ "is invalid"
    end

    test "does not update email on invalid email", %{conn: conn, password: password, user: user} do
      params = %{"email" => %{"email" => "invalid", "password" => password}}
      conn = Identity.Plug.log_in_user(conn, user)
      conn = post(conn, "/email/new", params)

      response = html_response(conn, 200)
      assert response =~ "must have the @ sign"
    end
  end

  describe "confirm_email/2" do
    setup %{conn: conn, user: user} do
      Identity.create_email(user, "new@example.com")
      assert_received {:confirm_email, ^user, encoded_token}

      conn = Identity.Plug.log_in_user(conn, user)
      %{conn: conn, token: encoded_token}
    end

    test "confirms email address", %{conn: conn, token: token} do
      conn = get(conn, "/email/#{token}")
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :info) =~ "confirmed"
      assert Repo.get_by(Identity.Schema.Email, email: "new@example.com").confirmed_at
    end

    test "does not confirm email with invalid token", %{conn: conn} do
      conn = get(conn, "/email/faketoken")
      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) =~ "Email confirmation link is invalid or it has expired"
    end
  end

  describe "new_user/2" do
    test "renders new user form", %{conn: conn} do
      conn = get(conn, "/user/new")
      assert html_response(conn, 200) =~ "form action=\"/user/new\""
    end

    test "redirects if already logged in", %{conn: conn, user: user} do
      conn =
        Identity.Plug.log_in_user(conn, user)
        |> get("/user/new")

      assert redirected_to(conn) == "/"
    end
  end

  describe "delete_email/2" do
    setup %{user: user} do
      email_one = Factory.insert(:email, user: user)
      email_two = Factory.insert(:email, user: user)
      %{email: email_one.email, email_two: email_two.email}
    end

    test "removes email address", %{conn: conn, email: email, user: user} do
      conn =
        conn
        |> Identity.Plug.log_in_user(user)
        |> delete("/user/email", %{"email" => email})

      assert redirected_to(conn) == "/"
      refute get_flash(conn, :error)
      refute Identity.get_user_by_email(email)
    end

    test "does not remove last email for user", %{
      conn: conn,
      email: email,
      email_two: email_two,
      user: user
    } do
      conn =
        conn
        |> Identity.Plug.log_in_user(user)
        |> delete("/user/email", %{"email" => email})
        |> delete("/user/email", %{"email" => email_two})

      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) =~ "at least one"
      refute Identity.get_user_by_email(email)
      assert Identity.get_user_by_email(email_two)
    end

    test "returns error for someone else's email", %{conn: conn, user: user} do
      other_user = Factory.insert(:user)
      email = Factory.insert(:email, user: other_user)

      conn =
        conn
        |> Identity.Plug.log_in_user(user)
        |> delete("/user/email", %{"email" => email.email})

      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) =~ "not found"
      assert Identity.get_user_by_email(email.email)
    end

    test "returns error for non-existent email", %{conn: conn, user: user} do
      conn =
        conn
        |> Identity.Plug.log_in_user(user)
        |> delete("/user/email", %{"email" => "fake@example.com"})

      assert redirected_to(conn) == "/"
      assert get_flash(conn, :error) =~ "not found"
    end
  end

  describe "create_user/2" do
    test "creates account and logs the user in", %{conn: conn} do
      password = Factory.valid_user_password()
      params = %{"user" => %{"email" => "test@example.com", "password" => password}}
      conn = post(conn, "/user/new", params)

      assert get_session(conn, :user_token)
      assert redirected_to(conn) =~ "/"

      # Should be logged in
      conn = get(conn, "/session/new")
      assert redirected_to(conn) =~ "/"
    end

    test "render errors for invalid data", %{conn: conn} do
      params = %{"user" => %{"email" => "invalid", "password" => "short"}}
      conn = post(conn, "/user/new", params)

      response = html_response(conn, 200)
      assert response =~ "must have the @ sign and no spaces"
      assert response =~ "should be at least 12 character"
    end
  end

  describe "edit_password/2" do
    test "renders password form", %{conn: conn, user: user} do
      Factory.insert(:basic_login, user: user)

      conn =
        Identity.Plug.log_in_user(conn, user)
        |> get("/user/password")

      response = html_response(conn, 200)
      assert response =~ "form action=\"/user/password\""
    end

    test "redirects if user is not logged in", %{conn: conn} do
      conn = get(conn, "/user/password")
      assert redirected_to(conn) == "/"
    end
  end

  describe "update_password/2" do
    setup %{user: user} do
      password = Factory.valid_user_password()
      Factory.insert(:basic_login, password: password, user: user)
      email = Factory.insert(:email, user: user)

      %{email: email.email, password: password}
    end

    test "updates the user password and resets tokens", %{
      conn: conn,
      email: email,
      password: password,
      user: user
    } do
      new_password = "new " <> Factory.valid_user_password()

      params = %{
        "password" => %{
          "current_password" => password,
          "password" => new_password,
          "password_confirmation" => new_password
        }
      }

      conn = Identity.Plug.log_in_user(conn, user)
      new_conn = put(conn, "/user/password", params)

      assert redirected_to(new_conn) == "/user/password"
      assert get_session(new_conn, :user_token) != get_session(conn, :user_token)
      assert get_flash(new_conn, :info) =~ "Password updated successfully"
      assert Identity.get_user_by_email_and_password(email, new_password)
    end

    test "does not update password on invalid data", %{conn: conn, user: user} do
      params = %{
        "password" => %{
          "current_password" => "invalid",
          "password" => "too short",
          "password_confirmation" => "does not match"
        }
      }

      conn = Identity.Plug.log_in_user(conn, user)
      old_password_conn = put(conn, "/user/password", params)

      response = html_response(old_password_conn, 200)
      assert response =~ "should be at least 12 character(s)"
      assert response =~ "does not match password"
      assert response =~ "is not valid"

      assert get_session(old_password_conn, :user_token) == get_session(conn, :user_token)
    end
  end
end

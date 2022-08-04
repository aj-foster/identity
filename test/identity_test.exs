defmodule IdentityTest do
  use Identity.DataCase, async: true

  alias Identity
  alias Identity.Schema.BasicLogin
  alias Identity.Schema.Email
  alias Identity.Schema.PasswordToken
  alias Identity.Schema.Session
  alias Identity.User

  #
  # Users
  #

  describe "get_user/1" do
    test "returns nil if ID is invalid" do
      assert is_nil(Identity.get_user("11111111-1111-1111-1111-111111111111"))
    end

    test "returns the user with the given ID" do
      %{id: user_id} = Factory.insert(:user)
      assert %User{id: ^user_id} = Identity.get_user(user_id)
    end
  end

  describe "get_user!/1" do
    test "raises if ID is invalid" do
      assert_raise Ecto.NoResultsError, fn ->
        Identity.get_user!("11111111-1111-1111-1111-111111111111")
      end
    end

    test "returns the user with the given ID" do
      %{id: user_id} = Factory.insert(:user)
      assert %User{id: ^user_id} = Identity.get_user!(user_id)
    end
  end

  describe "fetch_user/1" do
    test "returns error if ID is invalid" do
      assert {:error, :not_found} = Identity.fetch_user("11111111-1111-1111-1111-111111111111")
    end

    test "returns the user with the given ID" do
      %{id: user_id} = Factory.insert(:user)
      assert {:ok, %User{id: ^user_id}} = Identity.fetch_user(user_id)
    end
  end

  #
  # Basic Logins
  #

  describe "get_user_by_email_and_password/2" do
    test "does not return the user if the email does not exist" do
      refute Identity.get_user_by_email_and_password("unknown@example.com", "hello world!")
    end

    test "does not return the user if the password is not valid" do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)
      email = Factory.insert(:email, user: user)

      refute Identity.get_user_by_email_and_password(email.email, "invalid")
    end

    test "returns the user if the email and password are valid" do
      %{id: user_id} = user = Factory.insert(:user)
      password = Factory.valid_user_password()
      Factory.insert(:basic_login, password: password, user: user)
      %{email: email} = Factory.insert(:email, user: user)

      assert %User{id: ^user_id} = Identity.get_user_by_email_and_password(email, password)
    end
  end

  describe "validate_password/2" do
    setup do
      user = Factory.insert(:user)
      password = Factory.valid_user_password()
      Factory.insert(:basic_login, password: password, user: user)
      %{user: user, password: password}
    end

    test "returns true for a correct password", %{password: password, user: user} do
      assert Identity.correct_password?(user, password)
    end

    test "returns false for an incorrect password", %{user: user} do
      refute Identity.correct_password?(user, "wrong")
    end
  end

  describe "create_email_and_login_changeset/0" do
    test "returns a changeset" do
      assert %Ecto.Changeset{} = changeset = Identity.create_email_and_login_changeset()
      assert changeset.required == [:email, :password]
    end
  end

  describe "create_email_and_login/2" do
    setup do
      %{
        email: Factory.unique_user_email(),
        password: Factory.valid_user_password()
      }
    end

    test "requires email to be set" do
      {:error, changeset} = Identity.create_email_and_login(%{email: nil})
      assert %{email: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates email when given" do
      {:error, changeset} = Identity.create_email_and_login(%{email: "not valid"})
      assert %{email: ["must have the @ sign and no spaces"]} = errors_on(changeset)
    end

    test "validates maximum value for email for security" do
      too_long = String.duplicate("db", 100)
      {:error, changeset} = Identity.create_email_and_login(%{email: too_long})
      assert "should be at most 160 character(s)" in errors_on(changeset).email
    end

    test "validates email uniqueness" do
      %{email: email} = Factory.insert(:email)
      {:error, changeset} = Identity.create_email_and_login(%{email: email})
      assert "has already been taken" in errors_on(changeset).email

      # Now try with the upper cased email too, to check that email case is ignored.
      {:error, changeset} = Identity.create_email_and_login(%{email: String.upcase(email)})

      assert "has already been taken" in errors_on(changeset).email
    end

    test "requires password to be set", %{email: email} do
      {:error, changeset} = Identity.create_email_and_login(%{email: email})
      assert %{password: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates password when given", %{email: email} do
      {:error, changeset} =
        Identity.create_email_and_login(%{email: email, password: "not valid"})

      assert %{password: ["should be at least 12 character(s)"]} = errors_on(changeset)
    end

    test "validates maximum value for password for security", %{email: email} do
      too_long = String.duplicate("db", 100)

      {:error, changeset} = Identity.create_email_and_login(%{email: email, password: too_long})

      assert "should be at most 80 character(s)" in errors_on(changeset).password
    end

    test "registers users with a hashed password", %{email: email, password: password} do
      assert {:ok, _user} = Identity.create_email_and_login(%{email: email, password: password})

      assert [email_struct] = preload(Email, :user) |> Repo.all()
      assert email_struct.email == email
      assert is_nil(email_struct.confirmed_at)
      assert is_struct(email_struct.user, User)

      assert [login] = preload(BasicLogin, :user) |> Repo.all()
      assert is_binary(login.hashed_password)
      assert is_nil(login.password)
      assert is_struct(login.user, User)

      assert email_struct.user.id == login.user.id
    end

    test "associates an existing user", %{email: email, password: password} do
      user = Factory.insert(:user)

      assert {:ok, _user} =
               Identity.create_email_and_login(user, %{email: email, password: password})

      assert [email_struct] = preload(Email, :user) |> Repo.all()
      assert is_struct(email_struct.user, User)
      assert email_struct.user.id == user.id

      assert [login] = preload(BasicLogin, :user) |> Repo.all()
      assert is_struct(login.user, User)
      assert login.user.id == user.id
    end

    test "sends token through notification", %{email: email, password: password} do
      user = Factory.insert(:user)

      assert {:ok, _user} =
               Identity.create_email_and_login(user, %{email: email, password: password})

      assert_received {:confirm_email, ^user, token}
      assert {:ok, token} = Base.url_decode64(token, padding: false)
      assert user_token = Repo.get_by(Email, hashed_token: :crypto.hash(:sha256, token))
      assert user_token.user_id == user.id
    end
  end

  describe "create_login/2" do
    setup do
      %{
        password: Factory.valid_user_password(),
        user: Factory.insert(:user)
      }
    end

    test "requires password to be set", %{user: user} do
      {:error, changeset} = Identity.create_login(user, "")
      assert %{password: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates password when given", %{user: user} do
      {:error, changeset} = Identity.create_login(user, "not valid")
      assert %{password: ["should be at least 12 character(s)"]} = errors_on(changeset)
    end

    test "validates maximum value for password for security", %{user: user} do
      too_long = String.duplicate("db", 100)
      {:error, changeset} = Identity.create_login(user, too_long)
      assert "should be at most 80 character(s)" in errors_on(changeset).password
    end

    test "registers users with a hashed password", %{password: password, user: user} do
      assert {:ok, _user} = Identity.create_login(user, password)

      assert [login] = preload(BasicLogin, :user) |> Repo.all()
      assert is_binary(login.hashed_password)
      assert is_nil(login.password)
      assert is_struct(login.user, User)

      assert user.id == login.user.id
    end
  end

  describe "request_password_change/2" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)

      %{user: user}
    end

    test "returns a changeset", %{user: user} do
      assert %Ecto.Changeset{} = changeset = Identity.request_password_change(user)
      assert changeset.required == [:password]
    end

    test "allows fields to be set", %{user: user} do
      password = Factory.valid_user_password()
      changeset = Identity.request_password_change(user, %{password: password})

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :password) == password
      assert is_nil(Ecto.Changeset.get_change(changeset, :hashed_password))
    end
  end

  describe "update_password/2" do
    setup do
      user = Factory.insert(:user)
      email = Factory.insert(:email, user: user)
      Factory.insert(:basic_login, user: user)

      %{email: email.email, user: user}
    end

    test "validates password", %{user: user} do
      {:error, changeset} =
        Identity.update_password(user, Factory.valid_user_password(), %{
          password: "not valid",
          password_confirmation: "another"
        })

      assert %{
               password: ["should be at least 12 character(s)"],
               password_confirmation: ["does not match password"]
             } = errors_on(changeset)
    end

    test "validates maximum values for password for security", %{user: user} do
      too_long = String.duplicate("db", 100)

      {:error, changeset} =
        Identity.update_password(user, Factory.valid_user_password(), %{password: too_long})

      assert "should be at most 80 character(s)" in errors_on(changeset).password
    end

    test "validates current password", %{user: user} do
      {:error, changeset} =
        Identity.update_password(user, "invalid", %{password: Factory.valid_user_password()})

      assert %{current_password: ["is not valid"]} = errors_on(changeset)
    end

    test "updates the password", %{email: email, user: user} do
      {:ok, %User{}} =
        Identity.update_password(user, Factory.valid_user_password(), %{
          password: "new valid password"
        })

      assert Identity.get_user_by_email_and_password(email, "new valid password")
    end

    test "deletes all tokens for the given user", %{user: user} do
      Identity.create_session(user, "test")
      Identity.request_password_reset(user)

      {:ok, %User{}} =
        Identity.update_password(user, Factory.valid_user_password(), %{
          password: "new valid password"
        })

      refute Repo.get_by(PasswordToken, user_id: user.id)
      refute Repo.get_by(Session, user_id: user.id)
    end
  end

  describe "enable_2fa_changeset/1" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)

      %{user: user}
    end

    test "returns a changeset", %{user: user} do
      assert %Ecto.Changeset{} = changeset = Identity.enable_2fa_changeset(user)
      assert Ecto.Changeset.get_change(changeset, :otp_secret)
    end
  end

  describe "enable_2fa/2" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)
      changeset = Identity.enable_2fa_changeset(user)

      %{changeset: changeset, user: user}
    end

    test "validates required otp", %{changeset: changeset} do
      {:error, changeset} = Identity.enable_2fa(changeset, "")
      assert %{otp_code: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates otp as 6 digits number", %{changeset: changeset} do
      {:error, changeset} = Identity.enable_2fa(changeset, "1234567")
      assert %{otp_code: ["should be a 6 digit number"]} = errors_on(changeset)
    end

    test "validates otp against the secret", %{changeset: changeset} do
      {:error, changeset} = Identity.enable_2fa(changeset, "123456")
      assert %{otp_code: ["invalid code"]} = errors_on(changeset)
    end

    test "creates OTP settings and backup codes", %{changeset: changeset, user: user} do
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)

      assert {:ok, codes} = Identity.enable_2fa(changeset, otp)
      assert length(codes) == 10
      assert Enum.all?(codes, &(byte_size(&1) == 8))
      assert Enum.all?(codes, &(:binary.first(&1) in ?A..?Z))

      login = BasicLogin.get_login_by_user_query(user) |> Repo.one!()
      assert login.otp_secret == otp_secret
    end
  end

  describe "enabled_2fa?/1" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)

      %{user: user}
    end

    test "returns true when 2FA is enabled", %{user: user} do
      changeset = Identity.enable_2fa_changeset(user)
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)
      Identity.enable_2fa(changeset, otp)

      assert Identity.enabled_2fa?(user)
    end

    test "returns false when 2FA is not enabled", %{user: user} do
      refute Identity.enabled_2fa?(user)
    end
  end

  describe "valid_2fa?/2" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)

      changeset = Identity.enable_2fa_changeset(user)
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)
      {:ok, backup_codes} = Identity.enable_2fa(changeset, otp)

      %{backup_codes: backup_codes, code: otp, user: user}
    end

    test "returns true for a valid code", %{code: code, user: user} do
      assert Identity.valid_2fa?(user, code)

      login = BasicLogin.get_login_by_user_query(user) |> Repo.one!()
      assert login.last_used_otp_at
    end

    test "returns false for an invalid code", %{code: code, user: user} do
      code = if code == "123456", do: "123321", else: "123456"
      refute Identity.valid_2fa?(user, code)
    end

    test "returns false for a reused code", %{code: code, user: user} do
      assert Identity.valid_2fa?(user, code)
      refute Identity.valid_2fa?(user, code)
    end

    test "returns true for a valid backup code", %{backup_codes: backup_codes, user: user} do
      assert Identity.valid_2fa?(user, Enum.at(backup_codes, 0))
      assert Identity.valid_2fa?(user, Enum.at(backup_codes, 1))
      refute Identity.valid_2fa?(user, Enum.at(backup_codes, 1))
    end
  end

  describe "count_2fa_backup_codes/1" do
    test "counts remaining backup codes" do
      now = DateTime.utc_now()
      user = Factory.insert(:user)
      codes = [%BasicLogin.BackupCode{used_at: nil}, %BasicLogin.BackupCode{used_at: now}]
      Factory.insert(:basic_login, user: user, backup_codes: codes)

      assert Identity.count_2fa_backup_codes(user) == 1
    end
  end

  describe "regenerate_2fa_backup_codes/1" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)

      changeset = Identity.enable_2fa_changeset(user)
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)
      codes = Identity.enable_2fa(changeset, otp)

      %{codes: codes, user: user}
    end

    test "replaces backup codes", %{codes: codes, user: user} do
      assert {:ok, new_backup_codes} = Identity.regenerate_2fa_backup_codes(user)
      assert length(new_backup_codes) == 10
      assert new_backup_codes != codes
    end
  end

  describe "disable_2fa/1" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)

      changeset = Identity.enable_2fa_changeset(user)
      otp_secret = Ecto.Changeset.get_change(changeset, :otp_secret)
      otp = NimbleTOTP.verification_code(otp_secret)
      Identity.enable_2fa(changeset, otp)

      %{user: user}
    end

    test "removes OTP settings", %{user: user} do
      assert :ok = Identity.disable_2fa(user)
      login = BasicLogin.get_login_by_user_query(user) |> Repo.one!()
      assert is_nil(login.otp_secret)
    end

    test "returns error when user has no login" do
      user = Factory.insert(:user)
      assert {:error, :not_found} = Identity.disable_2fa(user)
    end
  end

  #
  # Emails
  #

  describe "list_emails/1" do
    test "returns email addresses for the given user" do
      user = Factory.insert(:user)
      [%{email: email_one}, %{email: email_two}] = Factory.insert_list(2, :email, user: user)
      Factory.insert(:email)

      emails = Identity.list_emails(user)
      assert length(emails) == 2
      assert MapSet.new(emails) == MapSet.new([email_one, email_two])
    end
  end

  describe "get_user_by_email/1" do
    test "does not return the user if the email does not exist" do
      refute Identity.get_user_by_email("unknown@example.com")
    end

    test "returns the user if the email exists" do
      %{email: email, user_id: user_id} = Factory.insert(:email)
      assert %User{id: ^user_id} = Identity.get_user_by_email(email)
    end
  end

  describe "create_email_changeset/0" do
    test "returns a changeset" do
      assert %Ecto.Changeset{errors: []} = Identity.create_email_changeset()
    end
  end

  describe "create_email/2" do
    setup do
      %{user: Factory.insert(:user)}
    end

    test "requires email to be set", %{user: user} do
      {:error, changeset} = Identity.create_email(user, "")
      assert %{email: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates email when given", %{user: user} do
      {:error, changeset} = Identity.create_email(user, "not valid")
      assert %{email: ["must have the @ sign and no spaces"]} = errors_on(changeset)
    end

    test "validates maximum values for email for security", %{user: user} do
      too_long = String.duplicate("db", 100)
      {:error, changeset} = Identity.create_email(user, too_long)
      assert "should be at most 160 character(s)" in errors_on(changeset).email
    end

    test "validates email uniqueness", %{user: user} do
      %{email: email} = Factory.insert(:email)
      {:error, changeset} = Identity.create_email(user, email)
      assert "has already been taken" in errors_on(changeset).email

      # Now try with the upper cased email too, to check that email case is ignored.
      {:error, changeset} = Identity.create_email(user, String.upcase(email))
      assert "has already been taken" in errors_on(changeset).email
    end

    test "sends token through notification", %{user: user} do
      assert :ok = Identity.create_email(user, "person@example.com")
      assert_received {:confirm_email, ^user, token}
      assert {:ok, token} = Base.url_decode64(token, padding: false)
      assert user_token = Repo.get_by(Email, hashed_token: :crypto.hash(:sha256, token))
      assert user_token.user_id == user.id
    end
  end

  describe "create_email/3" do
    setup do
      user = Factory.insert(:user)
      password = Factory.valid_user_password()
      Factory.insert(:basic_login, password: password, user: user)

      %{password: password, user: user}
    end

    test "validates a user's password", %{password: password, user: user} do
      assert {:error, changeset} = Identity.create_email(user, "person@example.com", "wrong")
      assert "is invalid" in errors_on(changeset).password

      assert :ok = Identity.create_email(user, "person@example.com", password)
    end
  end

  describe "confirm_email/1" do
    setup do
      %{email: Factory.insert(:email)}
    end

    test "confirms an email by its token", %{email: email} do
      assert {:ok, email} = Identity.confirm_email(email.token)
      assert %Email{confirmed_at: confirmed_at, hashed_token: nil} = email
      refute is_nil(confirmed_at)
    end

    test "returns error for invalid token" do
      assert {:error, :invalid} = Identity.confirm_email(<<0>>)
    end

    test "returns error for unknown token" do
      assert {:error, :not_found} = Identity.confirm_email("abcd")
    end
  end

  describe "delete_email/2" do
    setup do
      user = Factory.insert(:user)
      email = Factory.insert(:email, user: user)
      %{email: email, user: user}
    end

    test "removes email record", %{email: email, user: user} do
      Factory.insert(:email, user: user)
      assert :ok = Identity.delete_email(user, email.email)
    end

    test "returns error for only email", %{email: email, user: user} do
      assert {:error, :only_email} = Identity.delete_email(user, email.email)
    end

    test "returns error for only confirmed email", %{email: email, user: user} do
      Factory.insert(:email, user: user, confirmed_at: nil)
      assert {:error, :only_email} = Identity.delete_email(user, email.email)
    end

    test "returns error for unknown email", %{user: user} do
      assert {:error, :not_found} = Identity.delete_email(user, "unknown@example.com")
    end
  end

  #
  # Passwords
  #

  describe "request_password_reset/2" do
    setup do
      %{user: Factory.insert(:user)}
    end

    test "sends token through notification", %{user: user} do
      assert :ok = Identity.request_password_reset(user)
      assert_received {:reset_password, ^user, token}
      assert {:ok, token} = Base.url_decode64(token, padding: false)
      assert user_token = Repo.get_by(PasswordToken, hashed_token: :crypto.hash(:sha256, token))
      assert user_token.user_id == user.id
    end
  end

  describe "get_user_by_password_token/1" do
    setup do
      user = Factory.insert(:user)
      %PasswordToken{token: token} = Factory.insert(:password_token, user: user)

      %{user: user, token: token}
    end

    test "returns the user with valid token", %{user: %{id: id}, token: token} do
      assert %User{id: ^id} = Identity.get_user_by_password_token(token)
      assert Repo.get_by(PasswordToken, user_id: id)
    end

    test "does not return the user with invalid token", %{user: user} do
      refute Identity.get_user_by_password_token("oops")
      assert Repo.get_by(PasswordToken, user_id: user.id)
    end

    test "does not return the user if token expired", %{user: user, token: token} do
      {1, nil} = Repo.update_all(PasswordToken, set: [inserted_at: ~N[2020-01-01 00:00:00]])
      refute Identity.get_user_by_password_token(token)
      assert Repo.get_by(PasswordToken, user_id: user.id)
    end
  end

  describe "reset_password/2" do
    setup do
      user = Factory.insert(:user)
      Factory.insert(:basic_login, user: user)
      %Email{email: email} = Factory.insert(:email, user: user)

      %{email: email, user: user}
    end

    test "validates password", %{user: user} do
      {:error, changeset} =
        Identity.reset_password(user, %{
          password: "not valid",
          password_confirmation: "another"
        })

      assert %{
               password: ["should be at least 12 character(s)"],
               password_confirmation: ["does not match password"]
             } = errors_on(changeset)
    end

    test "validates maximum values for password for security", %{user: user} do
      too_long = String.duplicate("db", 100)
      {:error, changeset} = Identity.reset_password(user, %{password: too_long})
      assert "should be at most 80 character(s)" in errors_on(changeset).password
    end

    test "updates the password", %{email: email, user: user} do
      {:ok, _user} = Identity.reset_password(user, %{password: "new valid password"})
      login = Repo.get_by!(BasicLogin, user_id: user.id)
      assert is_nil(login.password)
      assert Identity.get_user_by_email_and_password(email, "new valid password")
    end

    test "deletes all tokens for the given user", %{user: user} do
      Identity.request_password_reset(user)
      {:ok, _} = Identity.reset_password(user, %{password: "new valid password"})
      refute Repo.get_by(PasswordToken, user_id: user.id)
    end

    test "deletes all sessions for the given user", %{user: user} do
      Identity.create_session(user, "test")
      {:ok, _} = Identity.reset_password(user, %{password: "new valid password"})
      refute Repo.get_by(Session, user_id: user.id)
    end
  end

  #
  # Sessions
  #

  describe "create_session/2" do
    setup do
      %{user: Factory.insert(:user)}
    end

    test "generates a token", %{user: user} do
      token = Identity.create_session(user, "test")
      assert Repo.get_by(Session, token: token)

      assert_raise Ecto.ConstraintError, fn ->
        Factory.insert(:session, token: token)
      end
    end
  end

  describe "get_user_by_session/1" do
    setup do
      user = Factory.insert(:user)
      token = Identity.create_session(user, "test")
      %{user: user, token: token}
    end

    test "returns user by token", %{user: user, token: token} do
      assert session_user = Identity.get_user_by_session(token)
      assert session_user.id == user.id
    end

    test "updates last active timestamp", %{token: token} do
      {1, nil} = Repo.update_all(Session, set: [last_active_at: ~U[2020-01-01 00:00:00Z]])
      assert Identity.get_user_by_session(token)
      assert session = Repo.get_by(Session, token: token)
      assert DateTime.compare(session.last_active_at, ~U[2020-01-01 00:00:00Z]) == :gt
    end

    test "does not return user for invalid token" do
      refute Identity.get_user_by_session("oops")
    end

    test "does not return user for expired token", %{token: token} do
      {1, nil} = Repo.update_all(Session, set: [inserted_at: ~U[2020-01-01 00:00:00Z]])
      refute Identity.get_user_by_session(token)
    end
  end

  describe "delete_session/1" do
    setup do
      user = Factory.insert(:user)
      token = Identity.create_session(user, "test")
      %{user: user, token: token}
    end

    test "revokes a session", %{token: token} do
      assert :ok = Identity.delete_session(token)
      assert [] = Repo.all(Session)
    end

    test "ignores an unknown token", %{token: token} do
      assert :ok = Identity.delete_session("oops")
      assert [%Session{token: ^token}] = Repo.all(Session)
    end
  end

  describe "delete_sessions_by_user/1" do
    setup do
      user = Factory.insert(:user)
      token1 = Identity.create_session(user, "test")
      token2 = Identity.create_session(user, "test")
      %{user: user, tokens: [token1, token2]}
    end

    test "deletes multiple sessions", %{user: user} do
      assert :ok = Identity.delete_sessions_by_user(user)
      assert [] = Repo.all(Session)
    end

    test "ignores a session-less user" do
      user = Factory.insert(:user)
      assert :ok = Identity.delete_sessions_by_user(user)
      assert [_, _] = Repo.all(Session)
    end
  end
end

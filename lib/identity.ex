defmodule Identity do
  @moduledoc """
  Provides access to users, sessions, and logins.
  """
  alias Identity.Changeset
  alias Identity.Schema.BasicLogin
  alias Identity.Schema.Email
  alias Identity.Schema.PasswordToken
  alias Identity.Schema.Session
  alias Identity.User

  #
  # Configuration
  #

  @compile {:inline, notifier: 0, repo: 0}
  # Note: this is a deliberate performance trade-off for the sake of runtime configuration.
  defp notifier, do: Application.get_env(:identity, :notifier, Identity.Notifier.Log)
  defp repo, do: Application.fetch_env!(:identity, :repo)

  #
  # Users
  #

  @doc """
  Get a single user by ID, or `nil` if the user does not exist.

  ## Examples

      iex> Identity.get_user("c4904ead-264d-4ba1-960d-68b49b8e0e10")
      %Identity.User{id: "c4904ead-264d-4ba1-960d-68b49b8e0e10"}

      iex> Identity.get_user("43cabfe9-1dfd-4946-a58e-9348a2aaf84b")
      nil

  """
  @doc section: :user
  @spec get_user(Ecto.UUID.t()) :: User.t() | nil
  def get_user(id), do: repo().get(User, id)

  @doc """
  Get a single user by ID, raising if the user does not exist.

    ## Examples

      iex> Identity.get_user("c4904ead-264d-4ba1-960d-68b49b8e0e10")
      %Identity.User{id: "c4904ead-264d-4ba1-960d-68b49b8e0e10"}

      iex> Identity.get_user("43cabfe9-1dfd-4946-a58e-9348a2aaf84b")
      ** (Ecto.NoResultsError)

  """
  @doc section: :user
  @spec get_user!(Ecto.UUID.t()) :: User.t() | no_return
  def get_user!(id), do: repo().get!(User, id)

  @doc """
  Get a single user by ID, returning `{:ok, user}` or `{:error, :not_found}`.

    ## Examples

      iex> Identity.get_user("c4904ead-264d-4ba1-960d-68b49b8e0e10")
      {:ok, %Identity.User{id: "c4904ead-264d-4ba1-960d-68b49b8e0e10"}}

      iex> Identity.get_user("43cabfe9-1dfd-4946-a58e-9348a2aaf84b")
      {:error, :not_found}

  """
  @doc section: :user
  @spec fetch_user(Ecto.UUID.t()) :: {:ok, User.t()} | {:error, :not_found}
  def fetch_user(id) do
    case repo().get(User, id) do
      %User{} = user -> {:ok, user}
      nil -> {:error, :not_found}
    end
  end

  #
  # Basic Logins
  #

  @doc """
  Get the user associated with a given `email` if the `password` matches.

  ## Examples

      iex> Identity.get_user_by_email_and_password("person@example.com", "password123")
      %User{id: "b8bca997-0fcf-4997-ad00-ed96ae1e0b1a"}

      iex> Identity.get_user_by_email_and_password("person@example.com", "invalid123")
      nil

  """
  @doc section: :login
  @spec get_user_by_email_and_password(String.t(), String.t()) :: User.t() | nil
  def get_user_by_email_and_password(email, password)
      when is_binary(email) and is_binary(password) do
    login = Email.get_login_by_email_query(email) |> repo().one()
    if BasicLogin.valid_password?(login, password), do: login.user
  end

  @doc """
  Validate whether `password` matches the given `user`, such as when a user is making changes to
  their email addresses.

  ## Examples

      iex> Identity.validate_password(user, "password")
      true

  """
  @doc section: :login
  @spec valid_password?(User.t(), String.t()) :: boolean
  def valid_password?(%User{} = user, password) when is_binary(password) do
    BasicLogin.get_login_by_user_query(user)
    |> repo().one()
    |> BasicLogin.valid_password?(password)
  end

  @doc """
  Create a changeset for registering a new email and password login.

  The fields in the returned changeset are compatible with `add_email_and_login/2`.

  ## Examples

      iex> Identity.add_email_and_login_changeset()
      #Ecto.Changeset<...>

  """
  @doc section: :login
  @spec add_email_and_login_changeset :: Ecto.Changeset.t(Changeset.email_password_data())
  def add_email_and_login_changeset do
    Changeset.email_and_password(%{})
  end

  @doc """
  Create a basic login and unconfirmed email for the given `user` or a brand new user.

  Use this function with an existing user to add email/password login if they currently log in with
  another method. Omit the user argument if someone registers for a new account. If desired,
  confirmation of the email can be required using the notifier and `confirm_email/1`. See
  `c:Identity.Notifier.confirm_email/2`.

  ## Changeset

  In case of error, this function returns a schemaless changeset with `:email` and `:password`
  fields. Use `add_email_and_login_changeset/0` to get a blank copy of this changeset for
  rendering a form.

  ## Examples

      iex> Identity.add_email_and_login(%{email: "person@example.com", password: "password123"})
      {:ok, %User{}}

  """
  @doc section: :login
  @spec add_email_and_login(%User{}, %{email: String.t(), password: String.t()}) ::
          {:ok, User.t()} | {:error, Ecto.Changeset.t(Changeset.email_password_data())}
  def add_email_and_login(user \\ %User{}, attrs) do
    changeset = Changeset.email_and_password(attrs)

    with {:ok, _changeset} <- Ecto.Changeset.apply_action(changeset, :insert) do
      email_changeset =
        %Email{}
        |> Email.registration_changeset(attrs)
        |> Ecto.Changeset.put_assoc(:user, user)

      Ecto.Multi.new()
      |> Ecto.Multi.insert(:email, email_changeset)
      |> Ecto.Multi.insert(:login, fn %{email: email} ->
        %BasicLogin{}
        |> BasicLogin.registration_changeset(attrs)
        |> Ecto.Changeset.put_assoc(:user, email.user)
      end)
      |> repo().transaction()
      |> case do
        {:ok, %{email: %Email{token: encoded_token, user: user}}} ->
          notifier().confirm_email(user, encoded_token)
          {:ok, user}

        {:error, _phase, changeset, _changes} ->
          {:error, Map.put(changeset, :errors, changeset.errors)}
      end
    end
  end

  @doc """
  Create a basic login for the given `user`.

  Use this function with an existing user to add email/password login if they currently log in with
  another method. If registering a brand new user, use `add_email_and_login/2` instead.

  ## Examples

      iex> Identity.register_password(user, password)
      {:ok, %User{}}

  """
  @doc section: :login
  @spec register_password(User.t(), String.t()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def register_password(user, password) do
    %BasicLogin{}
    |> BasicLogin.registration_changeset(%{password: password})
    |> Ecto.Changeset.put_assoc(:user, user)
    |> repo().insert()
  end

  @doc """
  Create a changeset for changing the user's password.

  ## Examples

      iex> Identity.request_password_change(user)
      %Ecto.Changeset{...}

  """
  @doc section: :login
  @spec request_password_change(User.t(), map) :: Ecto.Changeset.t()
  def request_password_change(%User{} = user, attrs \\ %{}) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> repo().one()
    BasicLogin.password_changeset(basic_login, attrs, hash_password: false)
  end

  @doc """
  Update the password for the given `user` and remove all active sessions and tokens.

  ## Examples

      iex> Identity.change_password(user, "password123", %{"password" => "new_password", "password_confirmation" => "new_password"})
      :ok

  """
  @doc section: :login
  @spec change_password(User.t(), String.t(), map) :: :ok | {:error, Ecto.Changeset.t()}
  def change_password(%User{} = user, current_password, attrs \\ %{}) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> repo().one()

    login_changeset =
      BasicLogin.password_changeset(basic_login, attrs)
      |> BasicLogin.validate_current_password(current_password)

    session_query = Session.list_by_user_query(user)
    reset_token_query = PasswordToken.list_by_user_query(user)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:login, login_changeset)
    |> Ecto.Multi.delete_all(:sessions, session_query)
    |> Ecto.Multi.delete_all(:password_resets, reset_token_query)
    |> repo().transaction()
    |> case do
      {:ok, _} -> :ok
      {:error, :login, changeset, _} -> {:error, changeset}
    end
  end

  #
  # Two-Factor
  #

  @doc """
  Generate a new 2FA secret to prompt the user for a code.

  The returned changeset includes an uncommitted `otp_secret`. This code can be used to create a
  QR code and generate a two-factor code for verifying the OTP setup using `enable_2fa/2`.

  ## Examples

      iex> Identity.request_enable_2fa(user)
      #Ecto.Changeset<changes: %{otp_secret: "**redacted**"}>

  """
  @doc section: :mfa
  @spec request_enable_2fa(User.t()) :: Ecto.Changeset.t(BasicLogin.t())
  def request_enable_2fa(user) do
    BasicLogin.get_login_by_user_query(user)
    |> repo().one()
    |> BasicLogin.generate_otp_secret_changeset()
  end

  @doc """
  Enable 2FA for the login changeset returned by `request_enable_2fa/1`.

  This function will first ensure the supplied 6-digit code is valid. If successful, a set of 10
  backup codes will be returned.

  ## Examples

      iex> Identity.enable_2fa(login_changeset, "123456")
      {:ok, ["abcd1234", ...]}

  """
  @doc section: :mfa
  @spec enable_2fa(Ecto.Changeset.t(BasicLogin.t()), String.t()) ::
          {:ok, [String.t()]} | {:error, Ecto.Changeset.t()}
  def enable_2fa(login_changeset, code) do
    BasicLogin.enable_2fa_changeset(login_changeset, code)
    |> BasicLogin.ensure_backup_codes()
    |> repo().update()
    |> case do
      {:ok, %BasicLogin{backup_codes: codes}} ->
        {:ok, Enum.map(codes, & &1.code)}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Check whether 2FA is enabled for the given `user`.

  ## Examples

      iex> Identity.enabled_2fa?(user)
      false

  """
  @doc section: :mfa
  @spec enabled_2fa?(User.t()) :: boolean
  def enabled_2fa?(user) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> repo().one()
    not is_nil(basic_login) and not is_nil(basic_login.otp_secret)
  end

  @doc """
  Validate the given 2FA or backup `code` for the given `user`.

  If a backup code is used, it will be marked as unavailable for future use.

  ## Examples

      iex> Identity.valid_2fa?(user, "123456")
      false

      iex> Identity.valid_2fa?(user, "abcd1234")
      true

  """
  @doc section: :mfa
  @spec valid_2fa?(User.t(), String.t()) :: boolean
  def valid_2fa?(user, code) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> repo().one()

    cond do
      BasicLogin.valid_otp_code?(basic_login, code) ->
        BasicLogin.set_last_used_otp_query(user)
        |> repo().update_all([])

        true

      changeset = BasicLogin.use_backup_code_changeset(basic_login, code) ->
        repo().update!(changeset)
        true

      true ->
        false
    end
  end

  @doc """
  Regenerate 2FA backup codes for the given `user`.

  All previous backup codes (if any) will no longer be valid.

  ## Examples

      iex> Identity.regenerate_2fa_backup_codes(user)
      {:ok, ["abcd1234", ...]}

  """
  @doc section: :mfa
  @spec regenerate_2fa_backup_codes(User.t()) ::
          {:ok, [String.t()]} | {:error, Ecto.Changeset.t()}
  def regenerate_2fa_backup_codes(user) do
    BasicLogin.get_login_by_user_query(user)
    |> repo().one()
    |> Ecto.Changeset.change()
    |> BasicLogin.regenerate_backup_codes()
    |> repo().update()
    |> case do
      {:ok, %BasicLogin{backup_codes: codes}} ->
        {:ok, Enum.map(codes, & &1.code)}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Disable 2FA for the given `user`.

  ## Examples

      iex> Identity.disable_2fa(user)
      :ok

  """
  @doc section: :mfa
  @spec disable_2fa(User.t()) :: :ok | {:error, :not_found}
  def disable_2fa(user) do
    BasicLogin.disable_2fa_query(user)
    |> repo().update_all([])
    |> case do
      {1, _} -> :ok
      {0, _} -> {:error, :not_found}
    end
  end

  #
  # Emails
  #

  @doc """
  Get the user associated with a given `email` address.

  ## Examples

      iex> Identity.get_user_by_email("person@example.com")
      %User{}

      iex> Identity.get_user_by_email("unknown@example.com")
      nil

  """
  @doc section: :email
  @spec get_user_by_email(String.t()) :: User.t() | nil
  def get_user_by_email(email) when is_binary(email) do
    Email.get_user_by_email_query(email)
    |> repo().one()
  end

  @doc """
  Create a changeset for adding a new email address to an existing user.

  ## Examples

      iex> Identity.request_register_email()
      #Ecto.Changeset<...>

  """
  @doc section: :email
  @spec request_register_email :: Ecto.Changeset.t()
  def request_register_email do
    Ecto.Changeset.change(%Email{})
  end

  @doc """
  Create an unconfirmed email for the given `user`.

  This function inserts a new email address record associated with the given user. If desired,
  confirmation of the email can be required using the notifier and `confirm_email/1`. See
  `c:Identity.Notifier.confirm_email/2`.

  See also `register_email/3` for a variation that requires a password.

  ## Examples

      iex> Identity.register_email(user, "person2@exaple.com")
      :ok

  """
  @doc section: :email
  @spec register_email(User.t(), String.t()) :: :ok | {:error, Ecto.Changeset.t() | any}
  def register_email(user, email) do
    changeset =
      %Email{}
      |> Email.registration_changeset(%{email: email})
      |> Ecto.Changeset.put_assoc(:user, user)

    with {:ok, %Email{token: encoded_token}} <- repo().insert(changeset) do
      notifier().confirm_email(user, encoded_token)
    end
  end

  @doc """
  Create an unconfirmed email for the given `user` after verifying the `password`.

  This function inserts a new email address record associated with the given user. If desired,
  confirmation of the email can be required using the notifier and `confirm_email/1`. See
  `c:Identity.Notifier.confirm_email/2`.

  See also `register_email/2` for a variation that does not require a password.

  ## Examples

      iex> Identity.register_email(user, "person2@exaple.com", "password")
      :ok

  """
  @doc section: :email
  @spec register_email(User.t(), String.t(), String.t()) ::
          :ok | {:error, Ecto.Changeset.t() | any}
  def register_email(user, email, password) do
    if valid_password?(user, password) do
      register_email(user, email)
    else
      request_register_email()
      |> Ecto.Changeset.add_error(:password, "is invalid")
      |> Ecto.Changeset.apply_action(:insert)
    end
  end

  @doc """
  Confirm an email by its encoded `token`.

  ## Examples

      iex> Identity.confirm_email("...")
      %Email{}

  """
  @doc section: :email
  @spec confirm_email(String.t()) :: {:ok, Email.t()} | {:error, :invalid | :not_found}
  def confirm_email(token) do
    with {:ok, query} <- Email.confirm_email_query(token),
         {1, [email]} <- repo().update_all(query, []) do
      {:ok, email}
    else
      :error -> {:error, :invalid}
      {0, _} -> {:error, :not_found}
    end
  end

  @doc """
  Remove a registered email, unless it is the only confirmed email for a user.

  If no emails are confirmed for this user, the only restriction enforced is that the user cannot
  delete their last remaining email address. Possible results are `:ok` when an email address is
  successfully removed, `{:error, :not_found}` if no such email exists for the given user, and
  `{:error, :only_email}` if deletion was restricted by the cases mentioned above.

  ## Examples

      iex> Identity.remove_email(user, "person@example.com")
      :ok

  """
  @doc section: :email
  @spec remove_email(User.t(), String.t()) :: :ok | {:error, :only_email | :not_found}
  def remove_email(user, email) do
    Email.list_emails_by_user_query(user.id)
    |> repo().all()
    |> Enum.split_with(&is_nil(&1.confirmed_at))
    |> case do
      # Only confirmed email address:
      {_, [%Email{email: ^email}]} ->
        {:error, :only_email}

      # Only email address:
      {[%Email{email: ^email}], []} ->
        {:error, :only_email}

      _ ->
        Email.get_by_email_query(email)
        |> repo().delete_all()
        |> case do
          {1, _} -> :ok
          {0, _} -> {:error, :not_found}
        end
    end
  end

  #
  # Passwords
  #

  @doc """
  Create a password reset token and notify the user.

  This is the first step in the password reset process. Once the user receives the reset token,
  identify / authenticate them with `get_user_by_password_token/1` and complete the process using
  `reset_password/2`. See `c:Identity.Notifier.reset_password/2` for more information about the
  user notification.

  ## Examples

      iex> Identity.request_password_reset(user)
      :ok

  """
  @doc section: :password_reset
  @spec request_password_reset(User.t()) :: :ok | {:error, any}
  def request_password_reset(%User{} = user) do
    %PasswordToken{token: encoded_token} =
      PasswordToken.initiate_reset_changeset()
      |> Ecto.Changeset.put_assoc(:user, user)
      |> repo().insert!()

    notifier().reset_password(user, encoded_token)
  end

  @doc """
  Get a user based on an encoded password reset `token`.

  ## Examples

      iex> Identity.get_user_by_password_token("...")
      %User{}

  """
  @doc section: :password_reset
  @spec get_user_by_password_token(String.t()) :: User.t() | nil
  def get_user_by_password_token(token) do
    with {:ok, query} <- PasswordToken.get_user_by_token_query(token),
         %User{} = user <- repo().one(query) do
      user
    else
      _ -> nil
    end
  end

  @doc """
  Reset a user's password.

  Assumes the user has already been identified and authenticated using a password reset token
  (see `get_user_by_password_token/1`). This final step ensures the new password is valid before
  saving.

  ## Examples

      iex> Identity.reset_password(user, %{"password" => "new_password", "password_confirmation" => "new_password})
      {:ok, %User{}}

  """
  @doc section: :password_reset
  @spec reset_password(User.t(), map) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def reset_password(user, attrs) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> repo().one()

    Ecto.Multi.new()
    |> Ecto.Multi.update(:password, BasicLogin.password_changeset(basic_login, attrs))
    |> Ecto.Multi.delete_all(:tokens, PasswordToken.list_by_user_query(user))
    |> Ecto.Multi.delete_all(:sessions, Session.list_by_user_query(user))
    |> repo().transaction()
    |> case do
      {:ok, _} -> {:ok, user}
      {:error, :password, changeset, _} -> {:error, changeset}
    end
  end

  #
  # Sessions
  #

  @doc """
  Create a session for the given `user` and `client`, returning an unencoded (non-printable)
  session token.

  The returned token is compatible with storing in a Plug session.

  ## Examples

      iex> Identity.create_session(user, "Firefox 100 on macOS 15")
      <<85, 185, 223, 71, 133, 31, 168, 86, 216, 65, 136, 158, ...>>

  """
  @doc section: :session
  @spec create_session(User.t(), String.t()) :: binary
  def create_session(user, client) do
    Session.build_token(user, client)
    |> repo().insert!()
    |> Map.get(:token)
  end

  @doc """
  Get the user associated with the given unencoded (non-printable) session `token`.

  The token is expected to be in the same form as returned by `create_session/2`. In addition to
  returning the user, this function also sets a "last active at" timestamp on the session.

  ## Examples

      iex> Identity.get_user_by_session(<<85, 185, 223, ...>>)
      %User{id: "5374240f-944c-47c9-83a8-cfafc01473cb"}

      iex> Identity.get_user_by_session(<<71, 133, 31, ...>>)
      nil

  """
  @doc section: :session
  @spec get_user_by_session(binary) :: User.t() | nil
  def get_user_by_session(token) do
    Session.verify_token_query(token)
    |> repo().update_all([])
    |> case do
      {1, [user]} -> user
      _ -> nil
    end
  end

  @doc """
  Revoke a single session by its `token`.

  Returns `:ok` regardless of whether a session was deleted.

  ## Examples

      iex> Identity.delete_session(<<85, 185, 223, ...>>)
      :ok

  """
  @doc section: :session
  @spec delete_session(binary) :: :ok
  def delete_session(token) do
    Session.get_by_token_query(token)
    |> repo().delete_all()

    :ok
  end

  @doc """
  Revoke all sessions for the given `user`.

  Returns `:ok` regardless of whether any sessions were deleted.

  ## Examples

      iex> Identity.delete_sessions_by_user(user)
      :ok

  """
  @doc section: :session
  @spec delete_sessions_by_user(User.t()) :: :ok
  def delete_sessions_by_user(user) do
    Session.list_by_user_query(user)
    |> repo().delete_all()

    :ok
  end
end

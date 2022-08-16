defmodule Identity do
  @moduledoc """
  Provides access to users, emails, sessions, and logins.

  Functions in this module deal with the underlying data in Identity. Out of the box, applications
  may not need to interface with this application directly. Instead, they may use functions from
  `Identity.Controller` (for Phoenix) or `Identity.Plug` (for Phoenix or Plug).

  ## Interface

  Where possible, Identity hides the underlying structs used to store Identity-related information.
  Your configured user module (see `Identity.Config`) is often the argument or response of a
  function in this module. Where necessary, custom changesets wrap the fields that are persisted
  to the database.

  If you find yourself working with the underlying structs directly, querying their tables, or
  otherwise peeking behind the curtain (except for curiosity, of course), please reach out to the
  maintainers and share the problem you are trying to solve. It might be solvable for everyone.
  """
  import Ecto.Query
  import Identity.Config

  alias Identity.Changeset
  alias Identity.Schema.BasicLogin
  alias Identity.Schema.Email
  alias Identity.Schema.OAuthLogin
  alias Identity.Schema.PasswordToken
  alias Identity.Schema.Session
  alias Identity.User

  @user user_schema()

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
  def get_user(id), do: repo().get(@user, id)

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
  def get_user!(id), do: repo().get!(@user, id)

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
    case repo().get(@user, id) do
      %@user{} = user -> {:ok, user}
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

    if BasicLogin.correct_password?(login, password) do
      %@user{login.user | login: login}
    end
  end

  @doc """
  Validate whether `password` matches the given `user`, such as when a user is making changes to
  their email addresses.

  ## Examples

      iex> Identity.validate_password(user, "password")
      true

  """
  @doc section: :login
  @spec correct_password?(User.t(), String.t()) :: boolean
  def correct_password?(%@user{} = user, password) when is_binary(password) do
    get_login_by_user(user)
    |> BasicLogin.correct_password?(password)
  end

  @doc """
  Create a changeset for registering a new email and password login.

  The fields in the returned changeset are compatible with `create_email_and_login/2`.

  ## Examples

      iex> Identity.create_email_and_login_changeset()
      #Ecto.Changeset<...>

  """
  @doc section: :login
  @spec create_email_and_login_changeset :: Ecto.Changeset.t(Changeset.email_password_data())
  def create_email_and_login_changeset do
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
  fields. Use `create_email_and_login_changeset/0` to get a blank copy of this changeset for
  rendering a form.

  ## Examples

      iex> Identity.create_email_and_login(%{email: "person@example.com", password: "password123"})
      {:ok, %User{}}

  """
  @doc section: :login
  @spec create_email_and_login(User.new(), map) ::
          {:ok, User.t()} | {:error, Ecto.Changeset.t(Changeset.email_password_data())}
  def create_email_and_login(user \\ %@user{}, attrs) do
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
  another method. If registering a brand new user, use `create_email_and_login/2` instead.

  ## Examples

      iex> Identity.create_login(user, password)
      {:ok, %User{}}

  """
  @doc section: :login
  @spec create_login(User.t(), String.t()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def create_login(user, password) do
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
  def request_password_change(%@user{} = user, attrs \\ %{}) do
    get_login_by_user(user)
    |> BasicLogin.password_changeset(attrs, hash_password: false)
  end

  @doc """
  Update the password for the given `user` and remove all active sessions and tokens.

  ## Examples

      iex> Identity.update_password(user, "password123", %{"password" => "new_password", "password_confirmation" => "new_password"})
      {:ok, %User{}}

  """
  @doc section: :login
  @spec update_password(User.t(), String.t(), map) ::
          {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def update_password(%@user{} = user, current_password, attrs \\ %{}) do
    login_changeset =
      get_login_by_user(user)
      |> BasicLogin.password_changeset(attrs)
      |> BasicLogin.validate_current_password(current_password)

    session_query = Session.list_by_user_query(user)
    reset_token_query = PasswordToken.list_by_user_query(user)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:login, login_changeset)
    |> Ecto.Multi.delete_all(:sessions, session_query)
    |> Ecto.Multi.delete_all(:password_resets, reset_token_query)
    |> repo().transaction()
    |> case do
      {:ok, %{login: login}} -> {:ok, %@user{user | login: login}}
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

      iex> Identity.enable_2fa_changeset(user)
      #Ecto.Changeset<changes: %{otp_secret: "**redacted**"}>

  """
  @doc section: :mfa
  @spec enable_2fa_changeset :: Ecto.Changeset.t(BasicLogin.otp_secret_and_code_data())
  def enable_2fa_changeset do
    Changeset.otp_secret_and_code()
  end

  @doc """
  Enable 2FA for the given `user`.

  This function will first ensure the supplied 6-digit `otp_code` is valid compared to the
  `otp_secret`. If successful, a set of 10 backup codes will be returned.

  ## Changeset

  In case of error, this function returns a schemaless changeset with `:otp_code` and `:otp_secret`
  fields. Use `enable_2fa_changeset/0` to get a blank copy of this changeset for rendering a form.

  ## Examples

      iex> Identity.enable_2fa(user, %{"otp_secret" => <<...>>, "otp_code" => "123456"})
      {:ok, ["abcd1234", ...]}

  """
  @doc section: :mfa
  @spec enable_2fa(User.t(), map) :: {:ok, [String.t()]} | {:error, Ecto.Changeset.t()}
  def enable_2fa(user, attrs) do
    get_login_by_user(user)
    |> BasicLogin.enable_2fa_changeset(attrs)
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
    basic_login = get_login_by_user(user)
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
    basic_login = get_login_by_user(user)

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
  Count the number of unused 2FA backup codes remaining for the given `user`.

  Generate a new set of codes (and invalidate the existing codes) using
  `regenerate_2fa_backup_codes/1`.

  ## Examples

      iex> Identity.count_2fa_backup_codes(user)
      9

  """
  @doc section: :mfa
  @spec count_2fa_backup_codes(User.t()) :: non_neg_integer
  def count_2fa_backup_codes(user) do
    case get_login_by_user(user) do
      %BasicLogin{backup_codes: codes} -> Enum.count(codes, fn code -> is_nil(code.used_at) end)
      nil -> 0
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
    get_login_by_user(user)
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
  List email addresses for the given `user`.

  ## Examples

      iex> Identity.list_emails(user)
      ["one@example.com", "two@example.com"]

  """
  @doc section: :email
  @spec list_emails(User.t()) :: [String.t()]
  def list_emails(user) do
    Email.list_emails_by_user_query(user.id)
    |> repo().all()
    |> Enum.map(& &1.email)
  end

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

      iex> Identity.create_email_changeset()
      #Ecto.Changeset<...>

  """
  @doc section: :email
  @spec create_email_changeset :: Ecto.Changeset.t()
  def create_email_changeset do
    Ecto.Changeset.change(%Email{})
  end

  @doc """
  Create an unconfirmed email for the given `user`.

  This function inserts a new email address record associated with the given user. If desired,
  confirmation of the email can be required using the notifier and `confirm_email/1`. See
  `c:Identity.Notifier.confirm_email/2`.

  See also `create_email/3` for a variation that requires a password.

  ## Examples

      iex> Identity.create_email(user, "person2@exaple.com")
      :ok

  """
  @doc section: :email
  @spec create_email(User.t(), String.t()) :: :ok | {:error, Ecto.Changeset.t() | any}
  def create_email(user, email) do
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

  See also `create_email/2` for a variation that does not require a password.

  ## Examples

      iex> Identity.create_email(user, "person2@exaple.com", "password")
      :ok

  """
  @doc section: :email
  @spec create_email(User.t(), String.t(), String.t()) ::
          :ok | {:error, Ecto.Changeset.t() | any}
  def create_email(user, email, password) do
    if correct_password?(user, password) do
      create_email(user, email)
    else
      create_email_changeset()
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

      iex> Identity.delete_email(user, "person@example.com")
      :ok

  """
  @doc section: :email
  @spec delete_email(User.t(), String.t()) :: :ok | {:error, :only_email | :not_found}
  def delete_email(user, email) do
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
        |> where(user_id: ^user.id)
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
  def request_password_reset(%@user{} = user) do
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
         %@user{} = user <- repo().one(query) do
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

  #
  # OAuth
  #

  @doc """
  Get a user by the OAuth provider and provider's ID.

  ## Examples

      iex> Identity.get_user_by_oauth(:github, "12345")
      %User{id: "5374240f-944c-47c9-83a8-cfafc01473cb"}

      iex> Identity.get_user_by_oauth("apple", "me@example.com")
      nil

  """
  @doc section: :oauth
  @spec get_user_by_oauth(Ueberauth.Auth.t()) :: User.t() | nil
  def get_user_by_oauth(auth) do
    %{provider: provider, uid: provider_id} = auth

    OAuthLogin.get_by_provider_query(provider, provider_id)
    |> repo().one()
    |> case do
      %OAuthLogin{user: user} -> user
      nil -> nil
    end
  end

  @doc """
  Create or update an OAuth login for an existing or new user.

  This multi-purpose function serves all of the following cases:

    * Creating a new user with new OAuth information, such as when a user signs in for the first
      time. This occurs when no matching OAuth record is found and the `:user` option is `nil`.
    * Updating an existing user with new OAuth information, such as when a user adds a new OAuth
      provider to their account. This occurs when no matching OAuth record is found and the `:user`
      option is set to an existing user.
    * Updating existing OAuth information, such as when a user logs in to an OAuth provider with
      new scopes. This occurs when an OAuth record is found, and its associated user matches the
      one provided in the `:user` option.

  If a user is provided, but an existing OAuth record is found associated with a different user,
  `{:error, :incorrect_user}` is returned.

  ## Options

    * `:user` (user struct): User to associate with the new or updated OAuth information.

  """
  @doc section: :oauth
  @spec create_or_update_oauth(Ueberauth.Auth.t(), keyword) :: {:ok, User.t()} | {:error, any}
  def create_or_update_oauth(auth, opts \\ []) do
    %{provider: provider, uid: provider_id} = auth

    OAuthLogin.get_by_provider_query(provider, provider_id)
    |> repo().one()
    |> case do
      %OAuthLogin{user: user} = login ->
        if opts[:user] && user.id != opts[:user].id do
          {:error, :incorrect_user}
        else
          OAuthLogin.from_auth(login, auth)
          |> repo().update()
          |> case do
            {:ok, %OAuthLogin{user: user}} -> {:ok, user}
            {:error, changeset} -> {:error, changeset}
          end
        end

      nil ->
        user = opts[:user] || %@user{}

        OAuthLogin.from_auth(auth)
        |> Ecto.Changeset.put_assoc(:user, user)
        |> repo().insert()
        |> case do
          {:ok, %OAuthLogin{user: user}} -> {:ok, user}
          {:error, changeset} -> {:error, changeset}
        end
    end
  end

  #
  # Helpers
  #

  @spec get_login_by_user(User.t()) :: BasicLogin.t() | nil
  defp get_login_by_user(%User{login: %BasicLogin{} = login} = user) do
    %BasicLogin{login | user: user}
  end

  defp get_login_by_user(%User{} = user) do
    BasicLogin.get_login_by_user_query(user)
    |> repo().one()
    |> case do
      %BasicLogin{} = login -> %BasicLogin{login | user: user}
      nil -> nil
    end
  end
end

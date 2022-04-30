defmodule Identity do
  @moduledoc """
  Provides access to users, sessions, and logins.
  """
  alias Identity.BasicLogin
  alias Identity.Email
  alias Identity.PasswordToken
  alias Identity.Session
  alias Identity.User

  @notifier Application.compile_env(:identity, :notifier, Identity.Notifier.Log)
  @repo Application.compile_env!(:identity, :repo)

  #
  # Users
  #

  @doc "Gets a single user by ID, raising if the user does not exist."
  @spec get_user!(Ecto.UUID.t()) :: User.t() | no_return
  def get_user!(id), do: @repo.get!(User, id)

  #
  # Basic Logins
  #

  @doc "Get the user associated with a given `email` if the `password` matches."
  @spec get_user_by_email_and_password(String.t(), String.t()) :: User.t() | nil
  def get_user_by_email_and_password(email, password)
      when is_binary(email) and is_binary(password) do
    login = Email.get_login_by_email_query(email) |> @repo.one()
    if BasicLogin.valid_password?(login, password), do: login.user
  end

  @doc "Create a basic login and unconfirmed email for the given `user` or a brand new user."
  @spec register_login(%User{}, %{email: String.t(), password: String.t()}) ::
          {:ok, %{email: Email.t(), login: BasicLogin.t()}}
          | {:error, atom, Ecto.Changeset.t(), map}
  def register_login(user \\ %User{}, attrs) do
    email_changeset =
      %Email{}
      |> Email.registration_changeset(attrs)
      |> Ecto.Changeset.put_assoc(:user, user)

    login_changeset =
      %BasicLogin{}
      |> BasicLogin.registration_changeset(attrs)
      |> Ecto.Changeset.put_assoc(:user, user)

    Ecto.Multi.new()
    |> Ecto.Multi.insert(:email, email_changeset)
    |> Ecto.Multi.insert(:login, login_changeset)
    |> @repo.transaction()
  end

  @doc "Create a changeset for changing the user's password."
  @spec request_password_change(User.t(), map) :: Ecto.Changeset.t()
  def request_password_change(%User{} = user, attrs \\ %{}) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> @repo.one()
    BasicLogin.password_changeset(basic_login, attrs, hash_password: false)
  end

  @doc "Update the password for the given `user` and remove all active sessions and tokens."
  @spec change_password(User.t(), String.t(), map) :: :ok | {:error, Ecto.Changeset.t()}
  def change_password(%User{} = user, current_password, attrs \\ %{}) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> @repo.one()

    login_changeset =
      BasicLogin.password_changeset(basic_login, attrs)
      |> BasicLogin.validate_current_password(current_password)

    session_query = Session.list_by_user_query(user)
    reset_token_query = PasswordToken.list_by_user_query(user)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:login, login_changeset)
    |> Ecto.Multi.delete_all(:sessions, session_query)
    |> Ecto.Multi.delete_all(:password_resets, reset_token_query)
    |> @repo.transaction()
    |> case do
      {:ok, _} -> :ok
      {:error, :login, changeset, _} -> {:error, changeset}
    end
  end

  @doc "Generate a new 2FA secret to prompt the user for a code."
  @spec request_enable_2fa(User.t()) :: Ecto.Changeset.t(BasicLogin.t())
  def request_enable_2fa(user) do
    BasicLogin.get_login_by_user_query(user)
    |> @repo.one()
    |> BasicLogin.generate_otp_secret_changeset()
  end

  @doc """
  Enable 2FA for the login changeset returned by `request_enable_2fa/1`.

  This function will first ensure the supplied 6-digit code is valid. If successful, a set of 10
  backup codes will be returned.
  """
  @spec enable_2fa(Ecto.Changeset.t(BasicLogin.t()), String.t()) ::
          {:ok, [String.t()]} | {:error, Ecto.Changeset.t()}
  def enable_2fa(login_changeset, code) do
    BasicLogin.enable_2fa_changeset(login_changeset, code)
    |> BasicLogin.ensure_backup_codes()
    |> @repo.update()
    |> case do
      {:ok, %BasicLogin{backup_codes: codes}} ->
        {:ok, Enum.map(codes, & &1.code)}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc "Validate the given 2FA or backup `code` for the given `user`."
  @spec valid_2fa?(User.t(), String.t()) :: boolean
  def valid_2fa?(user, code) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> @repo.one()

    cond do
      BasicLogin.valid_otp_code?(basic_login, code) ->
        BasicLogin.set_last_used_otp_query(user)
        |> @repo.update_all([])

        true

      changeset = BasicLogin.use_backup_code_changeset(basic_login, code) ->
        @repo.update!(changeset)
        true

      true ->
        false
    end
  end

  @doc "Regenerate 2FA backup codes for the given `user`."
  @spec regenerate_2fa_backup_codes(User.t()) ::
          {:ok, [String.t()]} | {:error, Ecto.Changeset.t()}
  def regenerate_2fa_backup_codes(user) do
    BasicLogin.get_login_by_user_query(user)
    |> @repo.one()
    |> Ecto.Changeset.change()
    |> BasicLogin.regenerate_backup_codes()
    |> @repo.update()
    |> case do
      {:ok, %BasicLogin{backup_codes: codes}} ->
        {:ok, Enum.map(codes, & &1.code)}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc "Disable 2FA for the given `user`."
  @spec disable_2fa(User.t()) :: :ok | {:error, :not_found}
  def disable_2fa(user) do
    BasicLogin.disable_2fa_query(user)
    |> @repo.update_all([])
    |> case do
      {1, _} -> :ok
      {0, _} -> {:error, :not_found}
    end
  end

  #
  # Emails
  #

  @doc "Get the user associated with a given `email` address."
  @spec get_user_by_email(String.t()) :: User.t() | nil
  def get_user_by_email(email) when is_binary(email) do
    Email.get_user_by_email_query(email)
    |> @repo.one()
  end

  @doc "Create an unconfirmed email for the given `user`."
  @spec register_email(User.t(), String.t()) :: {:ok, Email.t()} | {:error, Ecto.Changeset.t()}
  def register_email(user, email) do
    %Email{}
    |> Email.registration_changeset(%{email: email})
    |> Ecto.Changeset.put_assoc(:user, user)
    |> @repo.insert()
  end

  @doc "Confirm an email by its encoded `token`."
  @spec confirm_email(String.t()) :: {:ok, Email.t()} | {:error, :invalid | :not_found}
  def confirm_email(token) do
    with {:ok, query} <- Email.confirm_email_query(token),
         {1, [email]} <- @repo.update_all(query, []) do
      {:ok, email}
    else
      :error -> {:error, :invalid}
      {0, _} -> {:error, :not_found}
    end
  end

  @doc "Remove a registered email, unless it is the only confirmed email for a user."
  @spec remove_email(User.t(), String.t()) :: :ok | {:error, :only_email | :not_found}
  def remove_email(user, email) do
    Email.list_emails_by_user_query(user.id)
    |> @repo.all()
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
        |> @repo.delete_all()
        |> case do
          {1, _} -> :ok
          {0, _} -> {:error, :not_found}
        end
    end
  end

  #
  # Passwords
  #

  @spec request_password_reset(User.t()) :: {:ok, PasswordToken.t()}
  def request_password_reset(%User{} = user) do
    %PasswordToken{token: encoded_token} =
      token =
      PasswordToken.initiate_reset_changeset()
      |> Ecto.Changeset.put_assoc(:user, user)
      |> @repo.insert!()

    with :ok <- @notifier.reset_password(user, encoded_token) do
      {:ok, token}
    end
  end

  @doc "Get a user based on an encoded password reset `token`."
  @spec get_user_by_password_token(String.t()) :: User.t() | nil
  def get_user_by_password_token(token) do
    with {:ok, query} <- PasswordToken.get_user_by_token_query(token),
         %User{} = user <- @repo.one(query) do
      user
    else
      _ -> nil
    end
  end

  @doc "Reset a user's password."
  @spec reset_password(User.t(), map) :: {:ok, User.t()} | {:error, Changeset.t()}
  def reset_password(user, attrs) do
    basic_login = BasicLogin.get_login_by_user_query(user) |> @repo.one()

    Ecto.Multi.new()
    |> Ecto.Multi.update(:password, BasicLogin.password_changeset(basic_login, attrs))
    |> Ecto.Multi.delete_all(:tokens, PasswordToken.list_by_user_query(user))
    |> Ecto.Multi.delete_all(:sessions, Session.list_by_user_query(user))
    |> @repo.transaction()
    |> case do
      {:ok, _} -> {:ok, user}
      {:error, :password, changeset, _} -> {:error, changeset}
    end
  end

  #
  # Sessions
  #

  @doc "Create a session for the given `user` and `client`."
  @spec create_session(User.t(), String.t()) :: Session.t()
  def create_session(user, client) do
    Session.build_token(user, client)
    |> @repo.insert!()
  end

  @doc "Get the user associated with the given binary (non-printable) session `token`."
  @spec get_user_by_session(binary) :: User.t() | nil
  def get_user_by_session(token) do
    Session.verify_token_query(token)
    |> @repo.update_all([])
    |> case do
      {1, [user]} -> user
      _ -> nil
    end
  end

  @doc "Revoke a single session by its `token`."
  @spec delete_session(binary) :: :ok
  def delete_session(token) do
    Session.get_by_token_query(token)
    |> @repo.delete_all()

    :ok
  end

  @doc "Revoke all sessions for the given `user`."
  @spec delete_sessions_by_user(User.t()) :: :ok
  def delete_sessions_by_user(user) do
    Session.list_by_user_query(user)
    |> @repo.delete_all()

    :ok
  end
end

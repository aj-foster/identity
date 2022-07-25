defmodule Identity.Schema.BasicLogin do
  @moduledoc """
  Basic Logins represent the ability to log in with an email address and password.

  This struct is fully managed by Identity and its migrations. If you find yourself working with
  this struct directly or changing the underlying table, please share your use case with the
  maintainers of the library.
  """
  use Ecto.Schema
  import Ecto.Query
  import Identity.Config

  alias Ecto.Changeset
  alias Identity.Token
  alias Identity.User

  @user user_schema()

  @typedoc "Struct representing a basic (password) login method."
  @type t :: %__MODULE__{
          hashed_password: String.t(),
          id: Ecto.UUID.t(),
          inserted_at: DateTime.t(),
          last_active_at: DateTime.t(),
          last_used_otp_at: DateTime.t() | nil,
          otp_code: String.t() | nil,
          otp_secret: String.t() | nil,
          password: String.t() | nil,
          updated_at: DateTime.t(),
          user_id: Ecto.UUID.t(),
          user: Ecto.Schema.belongs_to(User.t())
        }

  @typedoc "Dataset with a single password field, such as during registration."
  @type password_data :: %{:password => String.t(), optional(any) => any}

  @derive {Inspect, except: [:password, :otp_secret]}
  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "user_basic_logins" do
    field :hashed_password, :string, redact: true
    field :last_active_at, :utc_datetime_usec
    field :last_used_otp_at, :utc_datetime_usec
    field :otp_code, :string, virtual: true, redact: true
    field :otp_secret, :binary, redact: true
    field :password, :string, virtual: true, redact: true

    embeds_many :backup_codes, BackupCode, on_replace: :delete do
      field :code, :string, redact: true
      field :used_at, :utc_datetime_usec
    end

    belongs_to(:user, @user)

    timestamps(type: :utc_datetime_usec)
  end

  #
  # Changesets
  #

  @doc """
  Changeset for registering a new email / password login method.

  ## Options

    * `:hash_password` - Hashes the password so it can be stored securely
      in the database and ensures the password field is cleared to prevent
      leaks in the logs. If password hashing is not needed and clearing the
      password field is not desired (like when using this changeset for
      validations on a LiveView form), this option can be set to `false`.
      Defaults to `true`.

  """
  @spec registration_changeset(%__MODULE__{}, map, Keyword.t()) :: Changeset.t(t)
  def registration_changeset(login, attrs, opts \\ []) do
    login
    |> Changeset.cast(attrs, [:password])
    |> validate_password(opts)
  end

  @spec validate_password(Changeset.t(password_data), Keyword.t()) :: Changeset.t(password_data)
  def validate_password(changeset, opts) do
    changeset
    |> Changeset.validate_required([:password])
    |> Changeset.validate_length(:password, min: 12, max: 80)
    |> maybe_hash_password(opts)
  end

  @spec maybe_hash_password(Changeset.t(password_data), Keyword.t()) :: Changeset.t(password_data)
  defp maybe_hash_password(changeset, opts) do
    hash_password? = Keyword.get(opts, :hash_password, true)
    password = Changeset.get_change(changeset, :password)

    if hash_password? && password && changeset.valid? do
      changeset
      |> Changeset.put_change(:hashed_password, Bcrypt.hash_pwd_salt(password))
      |> Changeset.delete_change(:password)
    else
      changeset
    end
  end

  @doc """
  Changeset for changing the password.

  ## Options

    * `:hash_password` - Hashes the password so it can be stored securely
      in the database and ensures the password field is cleared to prevent
      leaks in the logs. If password hashing is not needed and clearing the
      password field is not desired (like when using this changeset for
      validations on a LiveView form), this option can be set to `false`.
      Defaults to `true`.

  """
  @spec password_changeset(t, map, Keyword.t()) :: Changeset.t(t)
  def password_changeset(login, attrs, opts \\ []) do
    login
    |> Changeset.cast(attrs, [:password])
    |> Changeset.validate_confirmation(:password, message: "does not match password")
    |> validate_password(opts)
  end

  @doc "Verifies the password, or runs a similarly-timed function to prevent timing attacks."
  @spec correct_password?(t | nil, String.t()) :: boolean
  def correct_password?(%__MODULE__{hashed_password: hashed_password}, password)
      when is_binary(hashed_password) and byte_size(password) > 0 do
    Bcrypt.verify_pass(password, hashed_password)
  end

  def correct_password?(_, _) do
    Bcrypt.no_user_verify()
    false
  end

  @doc "Validate the current password when changing the password."
  @spec validate_current_password(Changeset.t(t), String.t()) :: Changeset.t(t)
  def validate_current_password(changeset, password) do
    if correct_password?(changeset.data, password) do
      changeset
    else
      Changeset.add_error(changeset, :current_password, "is not valid")
    end
  end

  @doc "Create a new OTP secret."
  @spec generate_otp_secret_changeset(t) :: Changeset.t(t)
  def generate_otp_secret_changeset(login) do
    Changeset.change(login, %{otp_secret: NimbleTOTP.secret()})
  end

  @doc "Validate the given `code` matches the OTP secret about to be persisted."
  @spec enable_2fa_changeset(Changeset.t(t), String.t()) :: Changeset.t(t)
  def enable_2fa_changeset(login_changeset, code) do
    login_changeset =
      login_changeset
      |> Changeset.put_change(:otp_code, code)
      |> Changeset.validate_required([:otp_code])
      |> Changeset.validate_format(:otp_code, ~r/^\d{6}$/, message: "should be a 6 digit number")

    secret = Changeset.get_field(login_changeset, :otp_secret)

    if login_changeset.valid? and not NimbleTOTP.valid?(secret, code) do
      Changeset.add_error(login_changeset, :otp_code, "invalid code")
    else
      login_changeset
    end
  end

  @doc "Verifies the OTP code against the saved secret."
  @spec valid_otp_code?(t, binary) :: boolean
  def valid_otp_code?(login, code)

  def valid_otp_code?(
        %__MODULE__{last_used_otp_at: timestamp, otp_secret: secret},
        <<code::binary-size(6)>>
      ) do
    NimbleTOTP.valid?(secret, code, since: timestamp)
  end

  def valid_otp_code?(_, _), do: false

  @doc "Require the presence of backup codes, even if some have been used."
  @spec ensure_backup_codes(Changeset.t(t)) :: Changeset.t(t)
  def ensure_backup_codes(login_changeset) do
    case Changeset.get_field(login_changeset, :backup_codes) do
      [] -> regenerate_backup_codes(login_changeset)
      _ -> login_changeset
    end
  end

  @doc "Create new backup codes and replace the existing codes, if any."
  @spec regenerate_backup_codes(Changeset.t(t)) :: Changeset.t(t)
  def regenerate_backup_codes(login_changeset) do
    codes =
      Token.generate_backup_codes()
      |> Enum.map(fn code -> %__MODULE__.BackupCode{code: code} end)

    Changeset.put_embed(login_changeset, :backup_codes, codes)
  end

  @doc "Validate and use a backup code."
  @spec use_backup_code_changeset(t, binary) :: Changeset.t(t) | nil
  def use_backup_code_changeset(login, <<code::binary-size(8)>>) do
    login.backup_codes
    |> Enum.map_reduce(false, fn backup, valid? ->
      if Plug.Crypto.secure_compare(backup.code, code) and is_nil(backup.used_at) do
        {Changeset.change(backup, %{used_at: DateTime.utc_now()}), true}
      else
        {backup, valid?}
      end
    end)
    |> case do
      {backup_codes, true} ->
        login
        |> Changeset.change()
        |> Changeset.put_embed(:backup_codes, backup_codes)

      {_, false} ->
        nil
    end
  end

  def use_backup_code_changeset(_login, _code), do: nil

  #
  # Queries
  #

  @doc "Get the login associated with the given `user`."
  @spec get_login_by_user_query(User.t()) :: Ecto.Query.t()
  def get_login_by_user_query(%@user{id: user_id}) do
    from(l in __MODULE__, as: :login)
    |> where(user_id: ^user_id)
  end

  @doc "Remove OTP-related data from the login associated with the given `user`."
  @spec set_last_used_otp_query(User.t()) :: Ecto.Query.t()
  def set_last_used_otp_query(user) do
    now = DateTime.utc_now()

    user
    |> get_login_by_user_query()
    |> update(set: [last_used_otp_at: ^now])
  end

  @doc "Remove OTP-related data from the login associated with the given `user`."
  @spec disable_2fa_query(User.t()) :: Ecto.Query.t()
  def disable_2fa_query(user) do
    user
    |> get_login_by_user_query()
    |> update(
      set: [
        backup_codes: fragment("'[]'::jsonb"),
        last_used_otp_at: nil,
        otp_secret: nil
      ]
    )
  end
end

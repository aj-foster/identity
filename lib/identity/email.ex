defmodule Identity.Email do
  @moduledoc """
  Emails represent addresses associated with a user.

  This struct is fully managed by Identity and its migrations. If you find yourself working with
  this struct directly or changing the underlying table, please share your use case with the
  maintainers of the library.
  """
  use Ecto.Schema
  import Ecto.Query

  alias Ecto.Changeset
  alias Identity.BasicLogin
  alias Identity.Token
  alias Identity.User

  @expiration_days 7

  @type t :: %__MODULE__{
          confirmed_at: DateTime.t() | nil,
          email: String.t(),
          generated_at: DateTime.t() | nil,
          hashed_token: binary,
          id: Ecto.UUID.t(),
          inserted_at: DateTime.t(),
          token: String.t(),
          user_id: Ecto.UUID.t(),
          user: Ecto.Schema.belongs_to(User.t())
        }

  @derive {Inspect, except: [:hashed_token]}
  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "user_emails" do
    field :confirmed_at, :utc_datetime_usec
    field :email, :string
    field :generated_at, :utc_datetime_usec
    field :hashed_token, :binary, redact: true
    field :token, :string, redact: true, virtual: true

    belongs_to(:user, User)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  #
  # Changesets
  #

  @doc "Register a new email address."
  @spec registration_changeset(%__MODULE__{}, map) :: Changeset.t(%__MODULE__{})
  def registration_changeset(struct, attrs) do
    struct
    |> Changeset.cast(attrs, [:email])
    |> validate_email()
    |> put_token()
  end

  @spec validate_email(Changeset.t(%__MODULE__{})) :: Changeset.t(%__MODULE__{})
  defp validate_email(changeset) do
    changeset
    |> Changeset.validate_required([:email])
    |> Changeset.validate_format(:email, ~r/^[^\s]+@[^\s]+$/,
      message: "must have the @ sign and no spaces"
    )
    |> Changeset.validate_length(:email, max: 160)
    |> Changeset.unsafe_validate_unique(:email, repo())
    |> Changeset.unique_constraint(:email)
  end

  @spec put_token(Changeset.t(%__MODULE__{})) :: Changeset.t(%__MODULE__{})
  defp put_token(changeset) do
    now = DateTime.utc_now()
    token = Token.generate_token()
    hashed_token = Token.hash_token(token)

    changeset
    |> Changeset.put_change(:generated_at, now)
    |> Changeset.put_change(:hashed_token, hashed_token)
    |> Changeset.put_change(:token, Base.url_encode64(token, padding: false))
  end

  #
  # Queries
  #

  @doc "Get the record associated with the given `email` address."
  @spec get_by_email_query(String.t()) :: Ecto.Query.t()
  def get_by_email_query(email) do
    from(t in __MODULE__, as: :email)
    |> where(email: ^email)
  end

  @doc "Get a basic login associated with the given `email` address."
  @spec get_login_by_email_query(String.t()) :: Ecto.Query.t()
  def get_login_by_email_query(email) do
    get_by_email_query(email)
    |> join(:inner, [email: e], u in User, on: u.id == e.user_id, as: :user)
    |> join(:inner, [user: u], l in BasicLogin, on: l.user_id == u.id, as: :login)
    |> select([login: l, user: u], merge(l, %{user: u}))
  end

  @doc "Get a user associated with the given `email` address."
  @spec get_user_by_email_query(String.t()) :: Ecto.Query.t()
  def get_user_by_email_query(email) do
    get_by_email_query(email)
    |> join(:inner, [email: e], u in User, on: u.id == e.user_id, as: :user)
    |> select([user: u], u)
  end

  @doc "Confirm an email by its `token`."
  @spec confirm_email_query(String.t()) :: {:ok, Ecto.Query.t()} | :error
  def confirm_email_query(token) do
    with {:ok, decoded_token} <- Base.url_decode64(token, padding: false) do
      hashed_token = Token.hash_token(decoded_token)
      now = DateTime.utc_now()

      query =
        from(t in __MODULE__, as: :email)
        |> where(hashed_token: ^hashed_token)
        |> where([email: e], e.generated_at > ago(@expiration_days, "day"))
        |> update(set: [confirmed_at: ^now, generated_at: nil, hashed_token: nil])
        |> select([email: e], e)

      {:ok, query}
    end
  end

  @doc "List all emails for a user, optionally returning only confirmed emails."
  @spec list_emails_by_user_query(Ecto.UUID.t(), keyword) :: Ecto.Query.t()
  def list_emails_by_user_query(user_id, opts \\ []) do
    from(t in __MODULE__, as: :email)
    |> where(user_id: ^user_id)
    |> filter_confirmed_emails(opts[:confirmed])
  end

  @spec filter_confirmed_emails(Ecto.Query.t(), boolean | nil) :: Ecto.Query.t()
  defp filter_confirmed_emails(query, confirmed?)
  defp filter_confirmed_emails(query, true), do: where(query, [e], not is_nil(e.confirmed_at))
  defp filter_confirmed_emails(query, _), do: query

  #
  # Configuration
  #

  @compile {:inline, repo: 0}
  defp repo, do: Application.fetch_env!(:identity, :repo)
end

defmodule Identity.Schema.PasswordToken do
  @moduledoc """
  Struct representing a password reset token for a basic login.

  > #### Note {:.info}
  >
  > This struct is fully managed by Identity and its migrations. If you find yourself working with
  > this struct directly or changing the underlying table, please share your use case with the
  > maintainers of the library.
  """
  use Ecto.Schema
  import Ecto.Query

  alias Ecto.Changeset
  alias Identity.Token
  alias Identity.User

  @expiration_days 1

  @typedoc "Struct representing password reset in progress."
  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          hashed_token: binary,
          token: String.t(),
          user_id: Ecto.UUID.t(),
          user: Ecto.Schema.belongs_to(User.t())
        }

  @derive {Inspect, except: [:hashed_token]}
  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "user_password_tokens" do
    field :hashed_token, :binary, redact: true
    field :token, :string, redact: true, virtual: true

    belongs_to(:user, Identity.User)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  #
  # Changesets
  #

  @doc "Create a new password reset token."
  @spec initiate_reset_changeset :: Changeset.t(%__MODULE__{})
  def initiate_reset_changeset do
    token = Token.generate_token()
    hashed_token = Token.hash_token(token)

    %__MODULE__{}
    |> Changeset.change()
    |> Changeset.put_change(:hashed_token, hashed_token)
    |> Changeset.put_change(:token, Base.url_encode64(token, padding: false))
  end

  #
  # Queries
  #

  @doc "Get all tokens associated with the given `user`."
  @spec list_by_user_query(User.t()) :: Ecto.Query.t()
  def list_by_user_query(%_{id: user_id}) do
    from(t in __MODULE__, as: :token)
    |> where(user_id: ^user_id)
  end

  @doc "Get a user by its corresponding password reset token."
  @spec get_user_by_token_query(String.t()) :: {:ok, Ecto.Query.t()} | :error
  def get_user_by_token_query(token) do
    with {:ok, decoded_token} <- Base.url_decode64(token, padding: false) do
      hashed_token = Token.hash_token(decoded_token)

      query =
        from(t in __MODULE__, as: :token)
        |> where(hashed_token: ^hashed_token)
        |> where([token: t], t.inserted_at > ago(@expiration_days, "day"))
        |> join(:inner, [token: t], u in assoc(t, :user), as: :user)
        |> select([user: u], u)

      {:ok, query}
    end
  end
end

defmodule Identity.Schema.Session do
  @moduledoc """
  Struct representing a revokable login session.

  > #### Note {:.info}
  >
  > This struct is fully managed by Identity and its migrations. If you find yourself working with
  > this struct directly or changing the underlying table, please share your use case with the
  > maintainers of the library.
  """
  use Ecto.Schema
  import Ecto.Query
  import Identity.Config

  alias Identity.Token
  alias Identity.User

  @expiration_seconds Application.compile_env(:identity, :remember_me)[:max_age] || 5_184_000

  @typedoc "Struct representing a user's login session."
  @type t :: %__MODULE__{
          client: String.t(),
          id: Ecto.UUID.t(),
          inserted_at: DateTime.t(),
          last_active_at: DateTime.t(),
          token: String.t(),
          user_id: Ecto.UUID.t(),
          user: Ecto.Schema.belongs_to(User.t())
        }

  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "user_sessions" do
    field :client, :string
    field :token, :binary, redact: true

    belongs_to :user, compile_time_user_schema()

    field :last_active_at, :utc_datetime_usec
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  #
  # Changesets
  #

  @doc "Create a new session struct."
  @spec build_token(User.t(), String.t()) :: %__MODULE__{}
  def build_token(user, client) do
    now = DateTime.utc_now()
    token = Token.generate_token()

    %__MODULE__{
      client: client,
      last_active_at: now,
      token: token,
      user_id: user.id
    }
  end

  #
  # Queries
  #

  @doc "List all sessions for a given `user`."
  @spec list_by_user_query(User.t()) :: Ecto.Query.t()
  def list_by_user_query(%_{id: user_id}) do
    from(s in __MODULE__, as: :session)
    |> where(user_id: ^user_id)
  end

  @doc "Get a session by its `token`."
  @spec get_by_token_query(binary) :: Ecto.Query.t()
  def get_by_token_query(token) do
    from(s in __MODULE__, as: :session)
    |> where(token: ^token)
  end

  @doc """
  Get the ID of the user associated with the given `token`. Call with `c:Ecto.Repo.update_all/3`.

  Also updates the session's `last_active_at` field.
  """
  @spec verify_token_query(binary) :: Ecto.Query.t()
  def verify_token_query(token) do
    now = DateTime.utc_now()

    get_by_token_query(token)
    |> where([session: s], s.inserted_at > ago(@expiration_seconds, "second"))
    |> update([session: s], set: [last_active_at: ^now])
    |> join(:inner, [session: s], u in assoc(s, :user), as: :user)
    |> select([user: u], u)
  end
end

defmodule Identity.Schema.OAuthLogin do
  @moduledoc """
  OAuth Logins represent the ability to log in with an external provider.

  > #### Note {:.info}
  >
  > This struct is fully managed by Identity and its migrations. If you find yourself working with
  > this struct directly or changing the underlying table, please share your use case with the
  > maintainers of the library.
  """
  use Ecto.Schema
  import Ecto.Query
  import Identity.Config

  alias Ecto.Changeset

  @user user_schema()

  @typedoc "Struct representing an OAuth login method."
  @type t :: %__MODULE__{}

  @derive {Inspect, except: [:token]}
  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "user_oauth_logins" do
    field :expires_at, :utc_datetime_usec
    field :last_active_at, :utc_datetime_usec
    field :provider, :string
    field :provider_id, :string
    field :scopes, {:array, :string}
    field :token, :string

    belongs_to(:user, @user)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  #
  # Changesets
  #

  @doc "Create a changeset for creating or updating an OAuth login."
  @spec from_auth(%__MODULE__{}, Ueberauth.Auth.t()) :: Ecto.Changeset.t(%__MODULE__{})
  def from_auth(login \\ %__MODULE__{}, auth) do
    attrs = %{
      expires_at: auth.credentials.expires_at,
      last_active_at: DateTime.utc_now(),
      provider: to_string(auth.provider),
      provider_id: to_string(auth.uid),
      scopes: auth.credentials.scopes,
      token: auth.credentials.token
    }

    login
    |> Changeset.cast(attrs, [
      :expires_at,
      :last_active_at,
      :provider,
      :provider_id,
      :scopes,
      :token
    ])
    |> Changeset.validate_required([:last_active_at, :provider, :provider_id, :token])
    |> Changeset.unique_constraint([:provider, :provider_id])
  end

  #
  # Queries
  #

  @doc "Get the OAuth login for the given `provider` and provider's ID."
  @spec get_by_provider_query(String.t() | atom, String.t()) :: Ecto.Query.t()
  def get_by_provider_query(provider, provider_id) do
    provider = to_string(provider)
    provider_id = to_string(provider_id)

    from(o in __MODULE__, as: :oauth)
    |> where(provider: ^provider, provider_id: ^provider_id)
    |> join(:inner, [oauth: o], u in assoc(o, :user), as: :user)
    |> preload([user: u], user: u)
  end
end

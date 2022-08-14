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
  import Identity.Config

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
end

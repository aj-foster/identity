defmodule Identity.User do
  @moduledoc """
  Struct representing a person in the real world.

  Identity provides `Identity.User` as a minimal schema to get started. It has a binary (UUID)
  primary key, and a collection of associations.

  ## Replacing this Schema

  Often, developers will want to store additional information related to users. This is possible
  using the `user` config (see `Identity.Config`). However, before adding a new field to the user
  schema, consider:

    1. Does Identity provide the same information in an associated struct already?
    2. Would an associated record be more appropriate?

  Keeping the user schema simple may increase the flexibility of the data in the future.

  ### Requirements

  Any custom schema should conform to two facts:

    1. It must have a binary (UUID) primary key called `:id`, and
    2. It must call the `Identity.Schema.user_associations/0` macro.

  Following is a minimal User schema:

      defmodule Identity.User do
        use Ecto.Schema
        import Identity.Schema

        @primary_key {:id, :binary_id, autogenerate: true}
        schema "users" do
          # ...
          user_associations()
        end
      end

  ### Configuration

  With the new user schema defined, it is necessary to tell Identity where to find it. Use the
  `:user` configuration key:

      # In config.exs or another compile-time configuration file
      config :identity,
        user: MyApp.User

  Note that this configuration must be specified at compile time. If changed, it is necessary to
  recompile identity with `mix deps.compile identity --force`. Runtime modification of the user
  schema is not supported.
  """
  use Ecto.Schema
  import Identity.Schema

  @typedoc "Generic user struct compatible with Identity."
  @type t :: %{
          :emails => Ecto.Schema.has_many(Identity.Schema.Email.t()),
          :id => Ecto.UUID.t(),
          :login => Ecto.Schema.has_one(Identity.Schema.BasicLogin.t() | nil),
          :oauth_logins => Ecto.Schema.has_many(Identity.Schema.OAuthLogin.t()),
          :password_token => Ecto.Schema.has_one(Identity.Schema.PasswordToken.t() | nil),
          :sessions => Ecto.Schema.has_many(Identity.Schema.Session.t()),
          optional(any) => any
        }

  @typedoc "Generic user struct compatible with Identity, possibly without a defined primary key."
  @type new :: %{
          :emails => Ecto.Schema.has_many(Identity.Schema.Email.t()),
          :id => Ecto.UUID.t() | nil,
          :login => Ecto.Schema.has_one(Identity.Schema.BasicLogin.t() | nil),
          :oauth_logins => Ecto.Schema.has_many(Identity.Schema.OAuthLogin.t()),
          :password_token => Ecto.Schema.has_one(Identity.Schema.PasswordToken.t() | nil),
          :sessions => Ecto.Schema.has_many(Identity.Schema.Session.t()),
          optional(any) => any
        }

  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "users" do
    user_associations()
  end
end

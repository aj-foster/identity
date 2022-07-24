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
  """
  use Ecto.Schema
  import Identity.Schema

  @type t :: %__MODULE__{
          emails: Ecto.Schema.has_many(Identity.Schema.Email.t()),
          id: Ecto.UUID.t(),
          login: Ecto.Schema.has_one(Identity.Schema.BasicLogin.t() | nil),
          password_token: Ecto.Schema.has_one(Identity.Schema.PasswordToken.t() | nil),
          sessions: Ecto.Schema.has_many(Identity.Schema.Session.t())
        }

  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "users" do
    user_associations()
  end
end

defmodule Identity.Test.User do
  use Ecto.Schema
  import Identity.Schema

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "users" do
    user_associations()
  end
end

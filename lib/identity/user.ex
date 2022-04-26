defmodule Identity.User do
  @moduledoc "Struct representing a person in the real world."
  use Ecto.Schema

  @type t :: %__MODULE__{
          id: Ecto.UUID.t()
        }

  @foreign_key_type :binary_id
  @primary_key {:id, :binary_id, autogenerate: true}
  schema("users", do: [])
end

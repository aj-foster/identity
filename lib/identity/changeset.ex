defmodule Identity.Changeset do
  @moduledoc false

  alias Ecto.Changeset
  alias Identity.Schema.BasicLogin
  alias Identity.Schema.Email

  @typedoc "Dataset with email and password fields, such as during registration."
  @type email_password_data :: %{:email => String.t(), optional(any) => any}

  @spec email_and_password(map) :: Ecto.Changeset.t(email_password_data)
  def email_and_password(attrs \\ %{}) do
    {%{}, %{email: :string, password: :string}}
    |> Changeset.cast(attrs, [:email, :password])
    |> BasicLogin.validate_password(hash_password: false)
    |> Email.validate_email()
  end
end

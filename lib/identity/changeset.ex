defmodule Identity.Changeset do
  @moduledoc """
  Changesets for common Identity operations.

  > #### Note {:.info}
  >
  > Functions in this module are used by the main `Identity` module. It is unlikely that you will
  > call these functions directly, unless you are reimplementing one of the core functions.

  When creating a new email and password login for a user, it's common to insert an email, login,
  and (possibly) user struct at the same time. Rather than expose the `Ecto.Multi` operation to
  consumers, Identity wraps these operations in schemaless changesets that focus on the input
  needed from the user.

  For example, `email_and_password/1` provides a changeset for registering a new email address and
  password login for a user. Although validation relates to two separate schemas,
  `Identity.Schema.BasicLogin` and `Identity.Schema.Email`, this module provides a single,
  consistent changeset for the operation.
  """
  alias Ecto.Changeset
  alias Identity.Schema.BasicLogin
  alias Identity.Schema.Email

  @typedoc "Dataset with email and password fields, as during registration."
  @type email_password_data :: %{:email => String.t(), optional(any) => any}

  @doc """
  Changeset for inserting a new `Identity.Schema.Email` and `Identity.Schema.BasicLogin` at once.

  This field operates on `t:email_password_data/0` and performs all of the relevant validation on
  each the `:email` and `:password` field. See `Identity.Schema.BasicLogin.validate_password/2` and
  `Identity.Schema.Email.validate_email/1` for more information.
  """
  @spec email_and_password(map) :: Ecto.Changeset.t(email_password_data)
  def email_and_password(attrs \\ %{}) do
    {%{}, %{email: :string, password: :string}}
    |> Changeset.cast(attrs, [:email, :password])
    |> BasicLogin.validate_password(hash_password: false)
    |> Email.validate_email()
  end
end

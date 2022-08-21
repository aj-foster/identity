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
  @type email_password_data :: %{:email => String.t(), :password => String.t()}

  @doc """
  Changeset for inserting a new `Identity.Schema.Email` and `Identity.Schema.BasicLogin` at once.

  This changeset operates on `t:email_password_data/0` and performs all of the relevant validation
  on each the `:email` and `:password` field. See `Identity.Schema.BasicLogin.validate_password/2`
  and `Identity.Schema.Email.validate_email/1` for more information.
  """
  @spec email_and_password(map) :: Ecto.Changeset.t(email_password_data)
  def email_and_password(attrs \\ %{}) do
    {%{}, %{email: :string, password: :string}}
    |> Changeset.cast(attrs, [:email, :password])
    |> BasicLogin.validate_password(hash_password: false)
    |> Email.validate_email()
  end

  @doc """
  Changeset for enabling 2FA on an `Identity.Schema.BasicLogin`.

  This changeset operates on `t:Identity.Schema.BasicLogin.otp_secret_and_code_data/0` and ensures
  the verification code is valid against the secret. If a secret was not supplied in the attributes,
  a new one is generated. See `Identity.Schema.BasicLogin.validate_otp_code/1` for more information.
  """
  @spec otp_secret_and_code(map) :: Ecto.Changeset.t(BasicLogin.otp_secret_and_code_data())
  def otp_secret_and_code(attrs \\ %{}) do
    attrs = Map.put_new_lazy(attrs, :otp_secret, &NimbleTOTP.secret/0)

    {%{}, %{otp_code: :string, otp_secret: :binary}}
    |> Changeset.cast(attrs, [:otp_code, :otp_secret])
    |> BasicLogin.validate_otp_code()
  end
end

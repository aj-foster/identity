defmodule Identity.Schema do
  @moduledoc """
  Provides helpers for writing custom schemas.

  Out of the box, Identity provides the following schemas:

    * `Identity.User`, representing an individual using the application with multiple login methods,
      email addresses, and sessions.
    * `Identity.Schema.BasicLogin`, representing a password login method.
    * `Identity.Schema.Email`, representing an email address used for logins, notifications, etc.
    * `Identity.Schema.PasswordToken`, representing a password reset token.
    * `Identity.Schema.Session`, representing an active login session.

  The schemas under `Identity.Schema.*` are fully managed by Identity and its migrations. If you
  find yourself working with this struct directly or changing the underlying table, please share
  your use case with the maintainers of the library.
  """

  @doc """
  Define Ecto associations for a custom User schema.

  If using a custom schema to replace `Identity.User`, calling this macro in the body of `schema`
  ensures the User is properly associated with Identity's internal schemas. This is necessary for
  efficient queries and easy preloading of data within Identity's core functions.

  ## Example

      defmodule MyApp.User do
        use Ecto.Schema
        import Identity.Schema

        @foreign_key_type :binary_id
        @primary_key {:id, :binary_id, autogenerate: true}
        schema "users" do
          # ...
          user_associations()
        end
      end
  """
  defmacro user_associations do
    quote do
      Ecto.Schema.has_many(:emails, Identity.Schema.Email, foreign_key: :user_id)
      Ecto.Schema.has_one(:login, Identity.Schema.BasicLogin, foreign_key: :user_id)
      Ecto.Schema.has_many(:oauth_logins, Identity.Schema.OAuthLogin, foreign_key: :user_id)
      Ecto.Schema.has_one(:password_token, Identity.Schema.PasswordToken, foreign_key: :user_id)
      Ecto.Schema.has_many(:sessions, Identity.Schema.Session, foreign_key: :user_id)
    end
  end
end

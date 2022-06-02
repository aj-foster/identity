defmodule Identity.Test.Factory do
  @moduledoc "Provides test data."
  use ExMachina.Ecto, repo: Identity.Test.Repo

  alias Identity.Token

  #
  # Identity
  #

  def basic_login_factory(attrs) do
    now = DateTime.utc_now()

    %Identity.Schema.BasicLogin{
      hashed_password: "$",
      id: Ecto.UUID.generate(),
      inserted_at: now,
      last_active_at: now,
      otp_secret: nil,
      password: valid_user_password(),
      updated_at: now,
      user: build(:user)
    }
    |> merge_attributes(attrs)
    |> set_password(attrs)
    |> evaluate_lazy_attributes()
  end

  def valid_user_password, do: "valid password"

  defp set_password(login, attrs) do
    password = Map.get(attrs, :password, login.password)
    Map.put(login, :hashed_password, Bcrypt.hash_pwd_salt(password))
  end

  def email_factory do
    now = DateTime.utc_now()
    token = Token.generate_token()
    hashed_token = Token.hash_token(token)

    %Identity.Schema.Email{
      confirmed_at: now,
      email: unique_user_email(),
      generated_at: now,
      hashed_token: hashed_token,
      id: Ecto.UUID.generate(),
      token: Base.url_encode64(token, padding: false),
      user: build(:user)
    }
  end

  def unique_user_email, do: sequence(:email, &"user-#{&1}@example.com")

  def password_token_factory do
    now = DateTime.utc_now()
    token = Token.generate_token()
    hashed_token = Token.hash_token(token)

    %Identity.Schema.PasswordToken{
      id: Ecto.UUID.generate(),
      inserted_at: now,
      hashed_token: hashed_token,
      token: Base.url_encode64(token, padding: false),
      user: build(:user)
    }
  end

  def session_factory do
    now = DateTime.utc_now()

    %Identity.Schema.Session{
      client: "test",
      id: Ecto.UUID.generate(),
      inserted_at: now,
      last_active_at: now,
      token: Identity.Token.generate_token(),
      user: build(:user)
    }
  end

  def user_factory do
    %Identity.User{
      id: Ecto.UUID.generate()
    }
  end
end

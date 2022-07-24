defmodule Identity.Schema.EmailTest do
  use Identity.DataCase, async: true

  alias Identity.Schema.Email

  describe "validate_email/1" do
    test "validates required email field" do
      changeset =
        {%{}, %{email: :string}}
        |> Ecto.Changeset.cast(%{"email" => ""}, [:email])
        |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "can't be blank" in errors[:email]

      %Email{}
      |> Ecto.Changeset.cast(%{"email" => ""}, [:email])
      |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "can't be blank" in errors[:email]
    end

    test "validates format of email field" do
      changeset =
        {%{}, %{email: :string}}
        |> Ecto.Changeset.cast(%{"email" => "test"}, [:email])
        |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "must have the @ sign and no spaces" in errors[:email]

      %Email{}
      |> Ecto.Changeset.cast(%{"email" => "test"}, [:email])
      |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "must have the @ sign and no spaces" in errors[:email]
    end

    test "validates length of email field" do
      long_value = :binary.copy("a", 80) <> "@" <> :binary.copy("b", 80)

      changeset =
        {%{}, %{email: :string}}
        |> Ecto.Changeset.cast(%{"email" => long_value}, [:email])
        |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "should be at most 160 character(s)" in errors[:email]

      %Email{}
      |> Ecto.Changeset.cast(%{"email" => long_value}, [:email])
      |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "should be at most 160 character(s)" in errors[:email]
    end

    test "validates uniqueness of email field" do
      Factory.insert(:email, email: "test@example.com")

      changeset =
        {%{}, %{email: :string}}
        |> Ecto.Changeset.cast(%{"email" => "test@example.com"}, [:email])
        |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "has already been taken" in errors[:email]

      %Email{}
      |> Ecto.Changeset.cast(%{"email" => "test@example.com"}, [:email])
      |> Email.validate_email()

      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:email]
      assert "has already been taken" in errors[:email]
    end

    test "accepts a valid email field" do
      changeset =
        {%{}, %{email: :string}}
        |> Ecto.Changeset.cast(%{"email" => "test@example.com"}, [:email])
        |> Email.validate_email()

      assert changeset.valid?
      errors = errors_on(changeset)
      refute errors[:email]

      %Email{}
      |> Ecto.Changeset.cast(%{"email" => "test@example.com"}, [:email])
      |> Email.validate_email()

      assert changeset.valid?
      errors = errors_on(changeset)
      refute errors[:email]
    end
  end
end

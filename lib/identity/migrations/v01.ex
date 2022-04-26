defmodule Identity.Migrations.V01 do
  @moduledoc false
  use Ecto.Migration

  def up(%{prefix: prefix, create_schema: create_schema}) do
    if create_schema, do: execute("CREATE SCHEMA IF NOT EXISTS #{prefix}")
    execute("CREATE EXTENSION IF NOT EXISTS citext;")

    #
    # Users
    #

    create_if_not_exists table(:users, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true)
    end

    #
    # Basic Logins
    #

    create_if_not_exists table(:user_basic_logins, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true)
      add(:backup_codes, :jsonb, null: false, default: fragment("'[]'::jsonb"))
      add(:hashed_password, :text, null: false)
      add(:last_used_otp_at, :utc_datetime_usec)
      add(:last_active_at, :utc_datetime_usec)
      add(:otp_secret, :bytea)

      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all, prefix: prefix),
        null: false
      )

      timestamps type: :utc_datetime_usec
    end

    create_if_not_exists(unique_index(:user_basic_logins, [:user_id], prefix: prefix))

    #
    # Emails
    #

    create_if_not_exists table(:user_emails, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true)
      add(:confirmed_at, :utc_datetime_usec)
      add(:email, :citext, null: false)
      add(:generated_at, :utc_datetime_usec)
      add(:hashed_token, :bytea)

      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all, prefix: prefix),
        null: false
      )

      timestamps type: :utc_datetime_usec, updated_at: false
    end

    create_if_not_exists(index(:user_emails, [:confirmed_at], prefix: prefix))
    create_if_not_exists(unique_index(:user_emails, [:email], prefix: prefix))
    create_if_not_exists(unique_index(:user_emails, [:hashed_token], prefix: prefix))
    create_if_not_exists(index(:user_emails, [:generated_at], prefix: prefix))
    create_if_not_exists(index(:user_emails, [:user_id], prefix: prefix))

    #
    # Password Tokens
    #

    create_if_not_exists table(:user_password_tokens, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true)
      add(:hashed_token, :bytea, null: false)

      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all, prefix: prefix),
        null: false
      )

      timestamps type: :utc_datetime_usec, updated_at: false
    end

    create_if_not_exists(unique_index(:user_password_tokens, [:hashed_token], prefix: prefix))
    create_if_not_exists(index(:user_password_tokens, [:user_id], prefix: prefix))

    #
    # Sessions
    #

    create_if_not_exists table(:user_sessions, primary_key: false, prefix: prefix) do
      add(:id, :uuid, primary_key: true)
      add(:client, :text, null: false)
      add(:last_active_at, :utc_datetime_usec, null: false)
      add(:token, :bytea, null: false)

      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all, prefix: prefix),
        null: false
      )

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create_if_not_exists(index(:user_sessions, [:user_id], prefix: prefix))
    create_if_not_exists(unique_index(:user_sessions, [:token], prefix: prefix))
  end

  def down(%{prefix: prefix}) do
    #
    # Sessions
    #

    drop_if_exists(index(:user_sessions, [:user_id], prefix: prefix))
    drop_if_exists(unique_index(:user_sessions, [:token], prefix: prefix))
    drop_if_exists(table(:user_sessions, prefix: prefix))

    #
    # Password Tokens
    #

    drop_if_exists(unique_index(:user_password_tokens, [:hashed_token], prefix: prefix))
    drop_if_exists(index(:user_password_tokens, [:user_id], prefix: prefix))
    drop_if_exists(table(:user_password_tokens, prefix: prefix))

    #
    # Emails
    #

    drop_if_exists(index(:user_emails, [:confirmed_at], prefix: prefix))
    drop_if_exists(unique_index(:user_emails, [:email], prefix: prefix))
    drop_if_exists(unique_index(:user_emails, [:hashed_token], prefix: prefix))
    drop_if_exists(index(:user_emails, [:generated_at], prefix: prefix))
    drop_if_exists(index(:user_emails, [:user_id], prefix: prefix))
    drop_if_exists(table(:user_emails, prefix: prefix))

    #
    # Basic Logins
    #

    drop_if_exists(unique_index(:user_basic_logins, [:user_id], prefix: prefix))
    drop_if_exists(table(:user_basic_logins, prefix: prefix))

    # Purposefully do not drop the users table.
  end
end

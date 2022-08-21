defmodule Identity.MixProject do
  use Mix.Project

  def project do
    [
      app: :identity,
      version: "0.1.0",
      elixir: "~> 1.13",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      name: "Identity",
      source_url: "https://github.com/aj-foster/identity",
      homepage_url: "https://github.com/aj-foster/identity",
      aliases: aliases(),
      deps: deps(),
      docs: docs()
    ]
  end

  def aliases do
    [
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end

  def application do
    if Mix.env() == :test do
      [
        extra_applications: [:logger, :ranch, :ex_machina, :plug, :plug_crypto],
        mod: {Identity.Test.Application, []}
      ]
    else
      [
        extra_applications: [:logger]
      ]
    end
  end

  defp deps do
    [
      {:bamboo, "~> 2.0", optional: true},
      {:bcrypt_elixir, "~> 3.0"},
      {:ecto_sql, "~> 3.0"},
      {:eqrcode, "~> 0.1.10", optional: true},
      {:ex_doc, "~> 0.28", only: :dev},
      {:ex_machina, "~> 2.7.0", only: [:dev, :test]},
      {:jason, "~> 1.0", optional: true},
      {:mime, "~> 1.0 or ~> 2.0", override: true, optional: true},
      {:mix_test_watch, "~> 1.0", only: [:test], runtime: false},
      {:nimble_totp, "~> 0.1", optional: true},
      {:phoenix, "~> 1.4", optional: true},
      {:phoenix_ecto, "~> 4.0", optional: true},
      {:phoenix_live_view, "~> 0.17.0", optional: true},
      {:phoenix_swoosh, "~> 1.0", optional: true},
      {:plug_cowboy, "~> 2.0", optional: true},
      {:plug_crypto, "~> 1.0"},
      {:postgrex, ">= 0.0.0"},
      {:swoosh, "~> 1.4", optional: true},
      {:ua_parser, "~> 1.8"},
      {:ueberauth, "~> 0.10", optional: true}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md": [title: "Overview"],
        "guides/getting-started.md": [title: "Getting Started"],
        "guides/progressive-replacement.md": [title: "Progressive Replacement"]
      ],
      groups_for_functions: [
        User: &(&1[:section] == :user),
        Login: &(&1[:section] == :login),
        Email: &(&1[:section] == :email),
        Session: &(&1[:section] == :session),
        "Two-Factor": &(&1[:section] == :mfa),
        "Password Reset": &(&1[:section] == :password_reset),
        OAuth: &(&1[:section] == :oauth)
      ],
      groups_for_modules: [
        Schemas: [Identity.User, ~r/Identity.Schema/],
        Notifiers: ~r/Identity.Notifier/,
        Internal: [Identity.Changeset, Identity.Token]
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end

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
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:bcrypt_elixir, "~> 3.0"},
      {:ecto_sql, "~> 3.0"},
      {:ex_doc, "~> 0.28", only: :dev},
      {:ex_machina, "~> 2.7.0", only: [:dev, :test]},
      {:jason, "~> 1.0", only: [:dev, :test]},
      {:mix_test_watch, "~> 1.0", only: [:test], runtime: false},
      {:nimble_totp, "~> 0.1", optional: true},
      {:plug_crypto, "~> 1.0"},
      {:postgrex, ">= 0.0.0"}
    ]
  end

  defp docs do
    [
      main: "Identity"
    ]
  end

  defp elixirc_paths(:dev), do: ["lib", "test/support"]
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end

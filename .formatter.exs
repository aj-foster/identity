# Used by "mix format"
[
  import_deps: [:ecto, :phoenix, :plug],
  inputs: ["{mix,.formatter}.exs", "{config,lib,priv,test}/**/*.{ex,exs,heex}"],
  plugins: [Phoenix.LiveView.HTMLFormatter],
  subdirectories: ["lib/migrations"]
]

if Code.ensure_loaded?(Phoenix.Endpoint) do
  defmodule Identity.Test.Endpoint do
    use Phoenix.Endpoint, otp_app: :identity

    @session_options [
      store: :cookie,
      key: "_apprise_key",
      signing_salt: "tSfoAn16"
    ]

    plug Plug.Session, @session_options
    plug Identity.Test.Router
  end
end
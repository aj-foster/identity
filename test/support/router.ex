if Code.ensure_loaded?(Phoenix.Router) do
  defmodule Identity.Test.Router do
    use Phoenix.Router

    scope "/" do
      get "/session/new", Identity.Controller, :new_session, as: :identity
      post "/session/new", Identity.Controller, :create_session, as: :identity
      get "/session/2fa", Identity.Controller, :new_2fa, as: :identity
    end
  end
end

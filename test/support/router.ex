if Code.ensure_loaded?(Phoenix.Router) do
  defmodule Identity.Test.Router do
    use Phoenix.Router

    scope "/" do
      get "/session/new", Identity.Controller, :new_session
    end
  end
end

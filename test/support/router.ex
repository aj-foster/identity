if Code.ensure_loaded?(Phoenix.Router) do
  defmodule Identity.Test.Router do
    use Phoenix.Router

    scope "/" do
      get "/session/new", Identity.Controller, :new_session, as: :identity
      post "/session/new", Identity.Controller, :create_session, as: :identity

      get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity
      post "/session/2fa", Identity.Controller, :validate_2fa, as: :identity

      get "/password/new", Identity.Controller, :new_password_token, as: :identity
      post "/password/new", Identity.Controller, :create_password_token, as: :identity
      get "/password/:token", Identity.Controller, :new_password, as: :identity
      put "/password/:token", Identity.Controller, :create_password, as: :identity

      get "/email/new", Identity.Controller, :new_email, as: :identity
      post "/email/new", Identity.Controller, :create_email, as: :identity
      get "/email/:token", Identity.Controller, :confirm_email, as: :identity

      get "/user/new", Identity.Controller, :new_user, as: :identity
      post "/user/new", Identity.Controller, :create_user, as: :identity
    end
  end
end

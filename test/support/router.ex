if Code.ensure_loaded?(Phoenix.Router) do
  defmodule Identity.Test.Router do
    use Phoenix.Router

    scope "/" do
      #
      # Session
      #

      get "/session/new", Identity.Controller, :new_session, as: :identity
      post "/session/new", Identity.Controller, :create_session, as: :identity

      get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity
      post "/session/2fa", Identity.Controller, :validate_2fa, as: :identity

      delete "/session", Identity.Controller, :delete_session, as: :identity

      #
      # Password Reset
      #

      get "/password/new", Identity.Controller, :new_password_token, as: :identity
      post "/password/new", Identity.Controller, :create_password_token, as: :identity

      get "/password/:token", Identity.Controller, :new_password, as: :identity
      put "/password/:token", Identity.Controller, :create_password, as: :identity

      #
      # Email Addresses
      #

      get "/email/new", Identity.Controller, :new_email, as: :identity
      post "/email/new", Identity.Controller, :create_email, as: :identity
      get "/email/:token", Identity.Controller, :confirm_email, as: :identity
      delete "/user/email", Identity.Controller, :delete_email, as: :identity

      #
      # User Settings
      #

      get "/user/new", Identity.Controller, :new_user, as: :identity
      post "/user/new", Identity.Controller, :create_user, as: :identity

      get "/user/password", Identity.Controller, :edit_password, as: :identity
      put "/user/password", Identity.Controller, :update_password, as: :identity

      get "/user/2fa/new", Identity.Controller, :new_2fa, as: :identity
      post "/user/2fa/new", Identity.Controller, :create_2fa, as: :identity
      get "/user/2fa", Identity.Controller, :show_2fa, as: :identity
      delete "/user/2fa", Identity.Controller, :delete_2fa, as: :identity
      put "/user/2fa/backup", Identity.Controller, :regenerate_2fa, as: :identity

      #
      # OAuth
      #

      get "/auth/:provider", Identity.Controller, :oauth_request, as: :identity
      get "/auth/:provider/callback", Identity.Controller, :oauth_callback, as: :identity
    end
  end
end

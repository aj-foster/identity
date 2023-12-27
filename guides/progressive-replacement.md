# Progressive Replacement

Identity follows a pattern of progressive replacement to enable **both** getting started quickly **and** customizing the experience.
This means it provides a lot of functionality out of the box with the assumption that developers will gradually replace its modules with their own.
For example, Identity supports all of these arrangements (including combinations of each):

1. Using `Identity.Controller` with its default view and templates to provide the login flow.
2. Using `Identity.Controller` with a custom view and templates for some or all of the actions.
3. Custom controller actions that use the same functions from `Identity.Plug`.
4. Custom controller actions and plug functions that use the same functions from `Identity`.

Eventually, most apps will even replace the core data functions provided by Identity.
Once that happens, congratulations! There's probably no reason to keep Identity installed.
Hopefully it enabled developers to focus on the core of the business during the early stages, and return to the details of authentication once the app started to take off.

The following describes some of the ways Identity enables this flow.

## Plugs, Controllers, and Templates

Identity provides controller actions and templates for common REST endpoints to get started quickly.
A complete router scope using these actions and templates looks like this:

```elixir
scope "/" do
  pipe_through :browser

  # Session
  get "/session/new", Identity.Controller, :new_session, as: :identity
  post "/session/new", Identity.Controller, :create_session, as: :identity

  get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity
  post "/session/2fa", Identity.Controller, :validate_2fa, as: :identity

  delete "/session", Identity.Controller, :delete_session, as: :identity

  # Password Reset
  get "/password/new", Identity.Controller, :new_password_token, as: :identity
  post "/password/new", Identity.Controller, :create_password_token, as: :identity

  get "/password/:token", Identity.Controller, :new_password, as: :identity
  put "/password/:token", Identity.Controller, :create_password, as: :identity

  # Email Addresses
  get "/email/new", Identity.Controller, :new_email, as: :identity
  post "/email/new", Identity.Controller, :create_email, as: :identity
  get "/email/:token", Identity.Controller, :confirm_email, as: :identity
  delete "/user/email", Identity.Controller, :delete_email, as: :identity

  # User Registration
  get "/user/new", Identity.Controller, :new_user, as: :identity
  post "/user/new", Identity.Controller, :create_user, as: :identity

  # User Settings
  get "/user/password", Identity.Controller, :edit_password, as: :identity
  put "/user/password", Identity.Controller, :update_password, as: :identity

  get "/user/2fa/new", Identity.Controller, :new_2fa, as: :identity
  post "/user/2fa/new", Identity.Controller, :create_2fa, as: :identity
  get "/user/2fa", Identity.Controller, :show_2fa, as: :identity
  delete "/user/2fa", Identity.Controller, :delete_2fa, as: :identity
  put "/user/2fa/backup", Identity.Controller, :regenerate_2fa, as: :identity

  # OAuth
  get "/auth/:provider", Identity.Controller, :oauth_request, as: :identity
  get "/auth/:provider/callback", Identity.Controller, :oauth_callback, as: :identity
end
```

Note that, as long as the `as: :identity` option is included and the action names remain the same, paths can be customized.

The routes specified above will use Identity's default templates, which render inside the application's normal layout view.
When it's time to create custom templates for these routes, create a new view module (for example, `MyAppWeb.IdentityView`) and put the view in the pipeline of the affected routes:

```elixir
pipeline :custom_identity do
  plug :put_view, MyAppWeb.IdentityView
end

scope "/" do
  pipe_through [:browser, :custom_identity]

  get "/session/new", Identity.Controller, :new_session, as: :identity
  post "/session/new", Identity.Controller, :create_session, as: :identity
  # ...
end
```

The provided controller actions will now render the new view's templates.
See `Identity.Controller` for more information about the assigns available in each call to render.

Of course, developers can also implement their own controller actions.
All three methods can be used in the same router:

```elixir
# Fully provided actions and templates
scope "/" do
  pipe_through :browser

  get "/session/new", Identity.Controller, :new_session, as: :identity
  post "/session/new", Identity.Controller, :create_session, as: :identity
end

scope "/" do
  pipe_through [:browser, :custom_identity]

  # Provided action with custom template
  get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity

  # Custom action using the same custom template
  post "/session/2fa", MyAppWeb.IdentityController, :validate_2fa, as: :identity
end
```

Identity-provided controller actions attempt to follow best practices and meet the needs of 80% of apps.
When developers discover the behavior that will differentiate their app, it's easy to replace the relevant templates and actions.

# Progressive Replacement

Identity follows a pattern of progressive replacement to enable **both** getting started quickly and customizing the experience.
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
  get "/session/new", Identity.Controller, :new_session, as: :identity
  post "/session/new", Identity.Controller, :create_session, as: :identity
  get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity
  post "/session/2fa", Identity.Controller, :validate_2fa, as: :identity
end
```

Note that, as long as the `as: :identity` option is included, the paths can be customized.

The routes specified above will use Identity's default templates, which render inside the application's normal layout view.
When it's time to create custom templates for these routes, create a new view module (for example, `MyAppWeb.IdentityView`) and put the view in the pipeline of the affected routes:

```elixir
pipeline :custom_identity do
  plug :put_view, MyAppWeb.IdentityView
end

scope "/" do
  pipe_through :custom_identity

  get "/session/new", Identity.Controller, :new_session, as: :identity
  post "/session/new", Identity.Controller, :create_session, as: :identity
  get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity
  post "/session/2fa", Identity.Controller, :validate_2fa, as: :identity
end
```

The provided controller actions will now render the new view's templates.
See `Identity.Controller` for more information about the assigns available in each call to render.

Of course, developers can also implement their own controller actions.
All three methods can be used in the same router:

```elixir
# Fully provided actions and templates
scope "/" do
  get "/session/new", Identity.Controller, :new_session, as: :identity
  post "/session/new", Identity.Controller, :create_session, as: :identity
end

scope "/" do
  pipe_through :custom_identity

  # Provided action with custom template
  get "/session/2fa", Identity.Controller, :pending_2fa, as: :identity

  # Custom action using the same custom template
  post "/session/2fa", MyAppWeb.IdentityController, :validate_2fa, as: :identity
end
```

Identity-provided controller actions attempt to follow best practices and meet the needs of 80% of apps.
When developers discover the behavior that will differentiate their app, it's easy to replace the relevant templates and actions.

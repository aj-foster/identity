# Getting Started

This guide assumes you are starting with a relatively bare application.
Additional notes are provided when Identity's setup might conflict with existing parts of your application.

## Install

Identity is an Elixir package that provides migrations and other helpers to assist with setup.
It is not currently available on Hex.pm.
For now, install it via GitHub by adding the following to the list of dependencies in `mix.exs` and running `mix deps.get`:

```elixir
def deps do
  [
    {:identity, github: "aj-foster/identity", branch: "main"}
  ]
end
```

## Migrate

After installation, create a new migration to add identity-related tables:

```shell
$ mix ecto.gen.migration add_identity
```

In the generated migration file, add the following:

```elixir
defmodule MyApp.Repo.Migrations.AddIdentity do
  use Ecto.Migration

  def up, do: Identity.Migrations.up()
  def down, do: Identity.Migrations.down()
end
```

Then run the migration:

```shell
$ mix ecto.migrate
```

Identity's migrations make liberal use of `create_if_not_exists`, meaning that existing tables (such as `users`) won't cause a problem during migration.
However, if there are conflicts, it is possible that Identity will not work as intended:

* As mentioned in `Identity.User`, any `users` table not created by Identity must have a binary (UUID) primary key called `id`.
* If other tables conflict, consider copying and modifying the provided migrations to start from the existing table structure.

## Configure

In order to interact with your application's database, Identity needs to know which module contains your database repo.
Following is a minimal configuration added to `config.exs`:

```elixir
config :identity, repo: MyApp.Repo
```

If you have an existing user schema, configure it using the `user` key:

```elixir
config :identity,
  repo: MyApp.Repo,
  user: MyApp.User
```

After the `user` configuration changes, it is necessary to recompile Identity using `mix deps.compile identity --force` in each Mix environment.

For information about additional configuration options, see `Identity.Config`.

## Add Routes

Identity provides controller actions and templates for all user tasks.
It is not necessary to use this provided functionality, but it is likely the fastest way to get up-and-running.

A full router, using all of Identity's features, looks like this:

```elixir
scope "/" do
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

Note that, as long as the `as: :identity` option is included and the action names remain the same, paths and scopes can be customized.

See [Progressive Replacement](progressive-replacement.md) for information about customizing the templates and actions.

## Protect Routes

For routes not provided by Identity, you can use plugs from `Identity.Plug` to enforce authentication rules.
For example:

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  # Import Identity plugs
  import Identity.Plug

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash

    # Add current_user assign; should be after :fetch_session
    plug :fetch_identity

    plug :put_root_layout, {MyAppWeb.LayoutView, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  scope "/", MyAppWeb do
    pipe_through [:browser, :redirect_if_authenticated]
    get "/public", PageController, :public
  end

  scope "/", MyAppWeb do
    pipe_through [:browser, :redirect_if_unauthenticated]
    get "/secret", PageController, :secret
  end

  # ...
end
```

Note that Identity-provided controller actions do not require the use of these plugs.
See `Identity.Plug` for more information about the available plugs and their options.

With the use of the `:fetch_identity` plug, you can use the `:current_user` assign to get the currently-authenticated user from a `%Plug.Conn{}` struct.

## (Optional) Set Up Two-Factor Auth

If you intend to use password-based authentication with your app, two-factor auth can be a great addition.
This functionality requires two additional dependencies:

```elixir
def deps do
  [
    # ...
    {:eqrcode, "~> 0.1.10"},
    {:nimble_totp, "~> 0.1"}
  ]
end
```

Respectively, `eqrcode` allows Identity to generate a QR code for easy 2FA enrollment, while `nimble_totp` handles generating secrets and checking codes.
After installing these additional dependencies, ensure Identity is recompiled with `mix deps.compile identity --force`.

Routes related to two-factor authentication are already included in the **Add Routes** section above.
If you use Identity-provided controller actions for login, they will already check if a user is enrolled in two-factor auth and redirect them appropriately.

## (Optional) Set Up Notifications

Some actions require communication with the user, usually via email.
For this, Identity uses a pluggable notification system.
Here are the available notifiers provided by Identity:

| Module | Description |
| ------ | ----------- |
| `Identity.Notifier.Log` | Default notifier. Simply logs a message via `Logger`. Great for development use. |
| `Identity.Notifier.Bamboo` | Email notifier using the [Bamboo](https://hexdocs.pm/bamboo/) library. Requires additional configuration. |
| `Identity.Notifier.Swoosh` | Email notifier using the [Swoosh](https://hexdocs.pm/swoosh/) library. Requires additional configuration. |
| `Identity.Notifier.Test` | Test notifier that sends a message to the current process when callbacks are called. Useful for testing purposes. |

To choose which notifier is active for your application, use the `notifier` key in the configuration:

```elixir
config :identity,
  # ...
  notifier: Identity.Notifier.Log  # This is the default
```

Notifiers adhere to the `Identity.Notifier` behaviour.
Check out that module's documentation for information about creating a custom implementation.

## (Optional) Set Up OAuth

Identity leverages [Ueberauth](https://hexdocs.pm/ueberauth/) and its collection of OAuth strategies.
To get started, install Ueberauth and the strategies you wish to use:

```elixir
def deps do
  [
    # ...
    {:ueberauth, "~> 0.10"},
    {:ueberauth_github, "~> 0.8"}
  ]
end
```

Note that it is common for strategies to require a lower version of Ueberauth than you wish to use.
Adding `override: true` to the `:ueberauth` dependency may be necessary.
After installing these additional dependencies, ensure Identity is recompiled with `mix deps.compile identity --force`.

Routes related to OAuth are already included in the **Add Routes** section above.
Remember to configure each of the Ueberauth strategy libraries according to their documentation.

## (Optional) Add Styles

Identity-provided templates use prefixed CSS classes (`.id_`) for easy styling.
If you wish to get off-the-ground quickly with some default styles, you can include Identity-provided CSS in your application:

```css
/* Assuming your CSS is in assets/css/ or similar. */
@import "../../deps/identity/priv/static/vanilla.css";
```

If you happen to use Tailwind for styling, there is a tailwind variant as well:

```css
@import "../../deps/identity/priv/static/tailwind.css";
```

These styles are minimal in design, and easily overridden with your own CSS.

## Conclusion

By the end of this work, you should have the basis of a feature-rich authentication system for your application.
Now you can focus on other — more important — things.
When you're ready to customize how auth looks and works, check out [Progressive Replacement](progressive-replacement.md).

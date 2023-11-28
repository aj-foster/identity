# Identity

Rapid authentication for new Elixir projects.

Identity takes the best of Phoenix's `mix phx.gen.auth`, combines the power of [Ueberauth](https://github.com/ueberauth/ueberauth) for OAuth, and adds additional features like multi-factor authentication.
It works to handle the logic of authentication so you can focus on more important parts of your app.
This includes:

* Login with an email and password
* Two-factor authentication
* Email confirmation
* Password resets
* Login with OAuth providers (using Ueberauth)

Some of the additional nice-to-have features include:

* Out-of-the-box implementations of controller actions and templates ([learn more](guides/progressive-replacement.md))
* Multiple email addresses per user
* Listing and deleting sessions
* Multiple OAuth providers per user
* Both email/password and OAuth logins for the same user
* Out-of-the-box implementations of email notifications for [Bamboo](https://hexdocs.pm/bamboo/) and [Swoosh](https://hexdocs.pm/swoosh/)

> All features are optional.
> Integrate what you want, and ignore the rest!

## Try It Out

If you want to integrate Identity into an existing application, see [Getting Started](guides/getting-started.md).
If you want to quickly see what Identity can do, follow these abbreviated instructions:

1. Generate a new Phoenix app using `mix phx.new` (learn more [here](https://hexdocs.pm/phoenix/Mix.Tasks.Phx.New.html)).
2. Identity is not currently available on Hex.pm, so install it via GitHub and run `mix deps.get`:

```elixir
def deps do
  [
    {:identity, github: "aj-foster/identity", branch: "main"}
  ]
end
```

3. Migrate the database with Identity's latest migrations (see `Identity.Migrations`).
4. Configure the `repo` option, for example `config :identity, repo: MyApp.Repo` (see `Identity.Config`).
5. Add Identity's provided controller actions to the application router (see `Identity.Controller`).
6. (Optional) Install `:eqrcode` and `:nimble_totp` to support 2FA.
7. (Optional) Install `:bamboo` or `:swoosh` to support email notifications and set the `notifier` config accordingly.
8. (Optional) Install `:ueberauth` and any desired Ueberauth providers to support OAuth.
9. (Optional) Add `@import "../../deps/identity/priv/static/vanilla.css";` to `app.css` to style the provided templates.

Run your application with `iex -S mix phx.server` and start at [http://localhost:4000/user/new](http://localhost:4000/user/new) to create a new user and start using your Identity-enabled application.

## Why?

With `phx.gen.auth`, adding authentication to a new Phoenix application became much easier.
However, it still requires developers to understand, integrate, and maintain the code.
This can provide friction for projects looking to get off the ground quickly.
What if something is implemented incorrectly?
What if it's unsafe?

Identity's goal is to allow developers to **get started quickly** and also **customize the experience** when time allows later on.
Through [Progressive Replacement](guides/progressive-replacement.md), Identity's out-of-the-box features can gradually be replaced with custom implementations as the application matures.

> Identity is made to eventually be replaced, but only when the developer is ready.

## Acknowledgments

This project uses, directly or indirectly, code from several other projects:

* [Phoenix, and `phx.gen.auth`](https://github.com/phoenixframework/phoenix/tree/2b5556f246c41e0ea96a0f1d52ea54f24221d982/priv/templates/phx.gen.auth): Copyright 2014 Chris McCord, released under the [MIT License](https://github.com/phoenixframework/phoenix/blob/2b5556f246c41e0ea96a0f1d52ea54f24221d982/LICENSE.md)
* [Bytepack](https://github.com/dashbitco/bytepack_archive/tree/79f8e62149d020f2afcc501592ed399f7ce7a60b): Copyright 2020 Dashbit, released under the [MIT License](https://github.com/dashbitco/bytepack_archive/blob/79f8e62149d020f2afcc501592ed399f7ce7a60b/README.md#license)
* [Oban](https://github.com/sorentwo/oban/tree/9b4861354f0189d548f4d5cd89273bc98f8eaede): Copyright 2019 Parker Selbert, released under the [Apache v2 License](https://github.com/sorentwo/oban/blob/9b4861354f0189d548f4d5cd89273bc98f8eaede/LICENSE.txt)

## License

This project is licensed under the MIT License.
For more information, see the [LICENSE](LICENSE) file.

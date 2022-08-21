# Identity

<!-- moduledoc -->

Rapid authentication for new Elixir projects.

Identity takes the best of Phoenix's `mix phx.gen.auth`, combines the power of [Ueberauth](https://github.com/ueberauth/ueberauth) for OAuth, and adds additional features like multi-factor authentication.
It works to handle the logic of authentication so you can focus on your business domain.
This includes:

* Login with an email and password
* Two-factor authentication
* Email confirmation
* Password resets
* Login with OAuth providers (using Ueberauth)

Some of the additional features include:

* Out-of-the-box implementations of controller actions and templates ([learn more](guides/progressive-replacement.md))
* Multiple email addresses per user
* Listing and deleting sessions
* Multiple OAuth providers per user
* Both email/password and OAuth for the same user
* Out-of-the-box implementations of email notifications for [Bamboo](https://hexdocs.pm/bamboo/) and [Swoosh](https://hexdocs.pm/swoosh/)

All features are optional.
Integrate what you want, and ignore the rest!

## Installation

Identity is not currently available on Hex.pm. For now, install it via GitHub:

```elixir
def deps do
  [
    {:identity, github: "aj-foster/identity", branch: "main"}
  ]
end
```

## Acknowledgments

This project uses, directly or indirectly, code from several other projects:

* [Phoenix, and the `phx.gen.auth` generator](https://github.com/phoenixframework/phoenix/tree/2b5556f246c41e0ea96a0f1d52ea54f24221d982/priv/templates/phx.gen.auth): Copyright 2014 Chris McCord, released under the [MIT License](https://github.com/phoenixframework/phoenix/blob/2b5556f246c41e0ea96a0f1d52ea54f24221d982/LICENSE.md)
* [Bytepack](https://github.com/dashbitco/bytepack_archive/tree/79f8e62149d020f2afcc501592ed399f7ce7a60b): Copyright 2020 Dashbit, released under the [MIT License](https://github.com/dashbitco/bytepack_archive/blob/79f8e62149d020f2afcc501592ed399f7ce7a60b/README.md#license)
* [Oban](https://github.com/sorentwo/oban/tree/9b4861354f0189d548f4d5cd89273bc98f8eaede): Copyright 2019 Parker Selbert, released under the [Apache v2 License](https://github.com/sorentwo/oban/blob/9b4861354f0189d548f4d5cd89273bc98f8eaede/LICENSE.txt)

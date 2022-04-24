# Identity

Rapid authentication for new Elixir projects.

Identity takes the best of Phoenix's `mix phx.gen.auth`, combines the power of [Ueberauth](https://github.com/ueberauth/ueberauth) for OAuth, and adds additional features like multi-factor authentication.
It works to handle the logic of authentication so you can focus on your business domain.

## Installation

Identity is not currently available on Hex.pm. For now, install it via GitHub:

```elixir
def deps do
  [
    {:identity, github: "aj-foster/identity", branch: "main"}
  ]
end
```

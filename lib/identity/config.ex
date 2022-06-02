defmodule Identity.Config do
  @moduledoc """
  Identity uses application config to specify several options.

      config :identity,
        repo: MyApp.Repo,
        user: MyApp.User

  ## Options

  Because of where and when they are used, some configuration options must be specified at compile
  time and may not be changed dynamically during runtime. If you require a compile-time config
  option to be changed at runtime, please reach out to the maintainers with additional information
  about your use case.

  | Option | Type | Scope | Description |
  | `notifier` | `module` | Runtime | Name of the module that implements the `Identity.Notifier` behaviour. This module will be called to send notifications to users. Default: `Identity.Notifier.Log` |
  | `paths` | `keyword` | Compilation | Relative paths used during the sign-in process. See **Paths** below. |
  | `remember_me` | `keyword` | Compilation | Cookie options for the "remember me" cookie. See **Remember Me** below. |
  | `repo` | `module` | Runtime | Name of the Ecto.Repo module for your application, for example `MyApp.Repo` |
  | `user` | `module` | Compilation | Name of the module that contains your User schema, for example `MyApp.Accounts.User`. This schema must have a UUID primary key called `id`. |

  Note that runtime configuration can be set in a runtime configuration file (such as `runtime.exs`)
  and changed dynamically using `Application.put_env/4`.

  ## Paths

  When using Identity with a Plug-based system, it is common to redirect users at various points
  in the login process. The `paths` configuration key allows customization of the routes used. All
  paths must be defined at compile time.

  | Key | Default | Description |
  | `sign_in` | `"/"` | Where to send unauthenticated users when they attempt to visit a privileged route. |
  | `after_sign_in` | `"/"` | Where to send users after they sign in (unless they were redirected from another route). |
  | `after_sign_out` | `"/"` | Where to send users after they sign out. |

  ## Remember Me

  When `remember_me: true` is passed to `Identity.Plug.log_in_user/3`, the user will have a cookie
  set using the options provided here. All options are passed to `Plug.Conn.put_resp_cookie/4`,
  except `name`, which is used as the name of the cookie.

  | Key | Default | Description |
  | `max_age` | `5_184_000` (60 days) | Time, in seconds, before the user is required to log in again. This setting also affects the expiration of persisted session records. |
  | `name` | `_identity_user_remember_me` | Name of the "remember me" cookie. |
  | `same_site` | `"Lax"` | Value of the [SameSite cookie attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite). |
  | `sign` | `true` | Whether to sign the cookie. See `Plug.Conn.put_resp_cookie/4` for more information. |

  """
end

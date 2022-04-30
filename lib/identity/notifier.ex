defmodule Identity.Notifier do
  @moduledoc """
  Defines a behaviour for communicating with users about changes to their account.

  In order to support multiple methods of sending notifications, this protocol defines a set of
  callbacks that run when notifiable actions occur. For example, when a user requests a password
  reset, Identity will run the `reset_password/2` callback from the configured notifier.

  ## Usage

  To create a notifier module, use the `Identity.Notifier` behaviour and implement its callbacks:

      defmodule MyApp.Notifier do
        use Identity.Notifier

        def reset_password(user, token) do
          # For example...
          MyApp.Mailer.send_password_reset(user, token)
        end
      end

  Then, configure this new module as the notifier:

      config :identity,
        notifier: MyApp.Notifier

  If a callback is not defined, the default action will be to print an informational log message
  using `Logger.info/1`. For a list of possible callbacks, see below.
  """
  alias Identity.User

  @doc false
  defmacro __using__(_) do
    quote do
      @behaviour Identity.Notifier

      def reset_password(user, token) do
        require Logger
        Logger.info("[Identity] Password reset initiated for user #{user.id}")
      end

      defoverridable reset_password: 2
    end
  end

  @doc "Send a password reset `token` and instructions to the given `user`."
  @callback reset_password(user :: User.t(), token :: String.t()) :: :ok | {:error, any}
end

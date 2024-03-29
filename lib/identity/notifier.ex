defmodule Identity.Notifier do
  @moduledoc """
  Defines a behaviour for communicating with users about changes to their account.

  In order to support multiple methods of sending notifications, this protocol defines a set of
  callbacks that run when notifiable actions occur. For example, when a user requests a password
  reset, Identity will run the `c:reset_password/2` callback from the configured notifier.

  ## Usage

  To create a notifier module, use the `Identity.Notifier` behaviour and implement its callbacks:

      defmodule MyApp.Notifier do
        use Identity.Notifier

        def reset_password(user, token) do
          # For example...
          MyApp.Mailer.send_password_reset(user, token)
        end

        # ...
      end

  Callbacks should return `:ok` or `{:error, reason}`. In general, error responses will be
  returned to the caller of the function that triggered the notification. For example, if the
  notifier fails to send a password reset token, then the caller of
  `Identity.request_password_reset/1` will receive that error as the return value.

  After defining the module, configure it as the notifier:

      config :identity,
        # ...
        notifier: MyApp.Notifier

  If any given callback is not defined, the default action will be to print an informational log
  message using `Logger.info/1`. For a list of possible callbacks, see below.

  ## Identity-Provided Notifiers

  Identity also provides several notifiers for quick integration. For development and testing,
  `Identity.Notifier.Log` simply prints a log message when notifications would occur. See also
  `Identity.Notifier.Bamboo` and `Identity.Notifier.Swoosh` for notifiers that use the most
  popular Phoenix-focused email libraries.
  """
  alias Identity.User

  @doc false
  defmacro __using__(_) do
    quote do
      @behaviour Identity.Notifier

      def confirm_email(email, _url) do
        require Logger
        Logger.info("[Identity] Email confirmation initiated for email #{email}")
      end

      def reset_password(user, _url) do
        require Logger
        Logger.info("[Identity] Password reset initiated for user #{user.id}")
      end

      defoverridable confirm_email: 2
      defoverridable reset_password: 2
    end
  end

  @doc """
  Send an email confirmation `url` and instructions to the given `email`.
  """
  @callback confirm_email(email :: String.t(), url :: String.t()) :: :ok | {:error, any}

  @doc """
  Send a password reset `url` and instructions to the given `user`.
  """
  @callback reset_password(user :: User.t(), url :: String.t()) :: :ok | {:error, any}
end

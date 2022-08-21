defmodule Identity.Notifier.Test do
  @moduledoc """
  Notifier that sends the current process a message when callbacks are called.

  ## Usage

  To use this notifier, configure it in the test environment (for example, `config/test.exs`):

      config :identity,
        # ...
        notifier: Identity.Notifier.Test

  Then, in a test, assert that a notification ocurred using `assert_received/1`:

      assert_received {:confirm_email, email, url}
      assert_received {:reset_password, user, url}

  You can pin message values (`email`, `user`, `url`) or make assertions on the matched values. Note
  that the assertion must take place in the same process that calls the notifier, so actions taken
  by separate Tasks and GenServers cannot be tested in this way.
  """
  use Identity.Notifier

  #
  # Notifier Callbacks
  #

  @impl Identity.Notifier
  def confirm_email(email, url) do
    send(self(), {:confirm_email, email, url})
    :ok
  end

  @impl Identity.Notifier
  def reset_password(user, url) do
    send(self(), {:reset_password, user, url})
    :ok
  end
end

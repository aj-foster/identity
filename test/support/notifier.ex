defmodule Identity.Test.Notifier do
  @moduledoc """
  Implementation of the Notifier behaviour that sends the current (test) process a message when
  callbacks are called.
  """
  use Identity.Notifier

  def confirm_email(email, url) do
    send(self(), {:confirm_email, email, url})
    :ok
  end

  def reset_password(user, url) do
    send(self(), {:reset_password, user, url})
    :ok
  end
end

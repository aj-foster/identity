defmodule Identity.Test.Notifier do
  @moduledoc """
  Implementation of the Notifier behaviour that sends the current (test) process a message when
  callbacks are called.
  """
  use Identity.Notifier

  def confirm_email(user, token) do
    send(self(), {:confirm_email, user, token})
    :ok
  end

  def reset_password(user, token) do
    send(self(), {:reset_password, user, token})
    :ok
  end
end

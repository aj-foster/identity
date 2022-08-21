if Code.ensure_loaded?(Swoosh) do
  defmodule Identity.Notifier.Swoosh do
    @moduledoc """
    Notifier that sends emails using `Swoosh`.

    > #### Warning {.warning}
    >
    > This module requires `Swoosh` to be installed. If you install Swoosh after Identity, then it
    > may be necessary to recompile the entire `:identity` dependency (not just your application).
    > This can be accomplished by running `mix deps.compile identity --force` in each Mix environment.
    > Be aware of this requirement if you use cached build artifacts in CI.

    For more information about notifiers, see `Identity.Notifier`.

    ## Configuration
    """
    use Identity.Notifier
    require Logger

    #
    # Notifier Callbacks
    #

    @impl Identity.Notifier
    def confirm_email(email, url) do
      base()
      |> Swoosh.Email.to([email])
      |> Swoosh.Email.subject("Confirm Your Email Address")
      |> Phoenix.Swoosh.render_body(:confirm_email,
        preview: "An email was added to your account. Please click to confirm it.",
        title: "Email Confirmation",
        url: url
      )
      |> mailer().deliver()
      |> case do
        {:ok, _email} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end

    @impl Identity.Notifier
    def reset_password(user, url) do
      emails = Identity.list_emails(user)

      base()
      |> Swoosh.Email.to(emails)
      |> Swoosh.Email.subject("Finish Resetting Your Password")
      |> Phoenix.Swoosh.render_body(:reset_password,
        preview: "Someone asked to reset your password. Please click to continue.",
        title: "Password Reset",
        url: url
      )
      |> mailer().deliver()
      |> case do
        {:ok, _email} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end

    #
    # Helpers
    #

    @spec base :: Swoosh.Email.t()
    defp base do
      Swoosh.Email.new(from: from_address())
      |> Phoenix.Swoosh.put_layout(layout_view())
      |> Phoenix.Swoosh.put_view(view())
    end

    #
    # Configuration
    #

    @spec from_address :: String.t() | no_return
    defp from_address do
      Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:from] ||
        raise "Identity.Notifier.Swoosh requires a `from` address"
    end

    @spec layout_view :: {module, atom}
    defp layout_view do
      layout = Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:layout]

      case layout do
        nil ->
          {Identity.Notifier.Swoosh.View, :email}

        {view, name} when is_atom(view) and is_atom(name) ->
          {view, name}

        view when is_atom(view) ->
          {view, :email}

        _ ->
          Logger.warning(
            "Invalid option `layout` for Identity.Notifier.Swoosh; should be module or module and template name"
          )

          {Identity.Notifier.Swoosh.View, :email}
      end
    end

    @spec mailer :: module | no_return
    defp mailer do
      Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:mailer] ||
        raise "Identity.Notifier.Swoosh requires a `mailer` module"
    end

    @spec view :: module
    defp view do
      view = Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:view]

      case view do
        nil ->
          Identity.Notifier.Swoosh.View

        view when is_atom(view) ->
          view

        _ ->
          Logger.warning("Invalid option `view` for Identity.Notifier.Swoosh; should be module")
          Identity.Notifier.Swoosh.View
      end
    end
  end
end

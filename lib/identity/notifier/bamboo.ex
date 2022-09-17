if Code.ensure_loaded?(Bamboo) do
  defmodule Identity.Notifier.Bamboo do
    @moduledoc """
    Notifier that sends emails using [Bamboo](https://hexdocs.pm/bamboo/).

    > #### Warning {:.warning}
    >
    > This module requires [Bamboo](https://hexdocs.pm/bamboo/) to be installed. If you install
    > Bamboo after Identity, then it may be necessary to recompile the entire `:identity` dependency
    > (not just your application). This can be accomplished by running
    > `mix deps.compile identity --force` in each Mix environment. Be aware of this requirement if
    > you use cached build artifacts in CI.

    For more information about notifiers, see `Identity.Notifier`.

    ## Usage

    To use this notifier, configure it in the relevant environment (for example, `config/prod.exs`):

        config :identity,
          # ...
          notifier: Identity.Notifier.Bamboo

    ## Templates

    Similar to Identity-provided controller actions, this notifier can be used in multiple ways
    depending on the level of customization desired:

    1. Using Identity-provided views and templates for email layout and contents.
    2. Using a custom layout view with the Identity-provided view and template for contents.
    3. Using custom layout and content views.

    In each case, the views are rendered with the following assigns:

    * `:preview`: Brief text that appears in the preview of an email client (not in the email itself).
    * `:title`: Header text in the body of the email
    * `:url`: URL for the email's action (confirm email, reset password, etc.).

    The provided templates are generic and do not necessarily confirm to CAN-SPAM or other relevant
    email requirements.

    ## Configuration

    The following configuration options can be passed to the module via application configuration:

        config :identity, Identity.Notifier.Bamboo,
          from: "no-reply@my.app",
          mailer: MyApp.Mailer

    | Option | Type | Description |
    | `from` | `string` | Email to use as the "from" address for outgoing emails. **Required**. |
    | `layout` | `module` or `{module, atom}` | Phoenix View (`module`) and template name (`atom`) to use while rendering email layout. If a module is provided, the `:email` template (`email.html.eex` and `email.text.eex`) will be used by default, same as `{module, :email}`. Defaults to Identity-provided templates. |
    | `mailer` | `module` | Bamboo Mailer module to use for delivery. The module must `use Bamboo.Mailer`. **Required**. |
    | `view` | `module` | Phoenix View to use while rendering email contents. Must provide `confirm_email` and `reset_password` templates for HTML and text emails. Defaults to Identity-provided templates. |

    """
    use Identity.Notifier
    # For`render/3`
    @doc false
    use Bamboo.Template
    require Logger

    #
    # Notifier Callbacks
    #

    @impl Identity.Notifier
    def confirm_email(email, url) do
      base()
      |> Bamboo.Email.to([email])
      |> Bamboo.Email.subject("Confirm Your Email Address")
      |> render(:confirm_email,
        preview: "An email was added to your account. Please click to confirm it.",
        title: "Email Confirmation",
        url: url
      )
      |> mailer().deliver_later()
      |> case do
        {:ok, _email} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end

    @impl Identity.Notifier
    def reset_password(user, url) do
      emails = Identity.list_emails(user)

      base()
      |> Bamboo.Email.to(emails)
      |> Bamboo.Email.subject("Finish Resetting Your Password")
      |> render(:reset_password,
        preview: "Someone asked to reset your password. Please click to continue.",
        title: "Password Reset",
        url: url
      )
      |> mailer().deliver_later()
      |> case do
        {:ok, _email} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end

    #
    # Helpers
    #

    @spec base :: Bamboo.Email.t()
    defp base do
      Bamboo.Email.new_email(from: from_address())
      |> Bamboo.Template.put_layout(layout_view())
      |> Bamboo.Template.put_view(view())
    end

    #
    # Configuration
    #

    @spec from_address :: String.t() | no_return
    defp from_address do
      Application.get_env(:identity, Identity.Notifier.Bamboo, [])[:from] ||
        raise "Identity.Notifier.Bamboo requires a `from` address"
    end

    @spec layout_view :: {module, atom}
    defp layout_view do
      layout = Application.get_env(:identity, Identity.Notifier.Bamboo, [])[:layout]

      case layout do
        nil ->
          {Identity.Notifier.Bamboo.View, :email}

        {view, name} when is_atom(view) and is_atom(name) ->
          {view, name}

        view when is_atom(view) ->
          {view, :email}

        _ ->
          Logger.warning(
            "Invalid option `layout` for Identity.Notifier.Bamboo; should be module or module and template name"
          )

          {Identity.Notifier.Bamboo.View, :email}
      end
    end

    @spec mailer :: module | no_return
    defp mailer do
      Application.get_env(:identity, Identity.Notifier.Bamboo, [])[:mailer] ||
        raise "Identity.Notifier.Bamboo requires a `mailer` module"
    end

    @spec view :: module
    defp view do
      view = Application.get_env(:identity, Identity.Notifier.Bamboo, [])[:view]

      case view do
        nil ->
          Identity.Notifier.Bamboo.View

        view when is_atom(view) ->
          view

        _ ->
          Logger.warning("Invalid option `view` for Identity.Notifier.Bamboo; should be module")
          Identity.Notifier.Bamboo.View
      end
    end
  end
end

if Code.ensure_loaded?(Swoosh) do
  defmodule Identity.Notifier.Swoosh do
    @moduledoc """
    Notifier that sends emails using `Swoosh`.

    > #### Warning {:.warning}
    >
    > This module requires `Swoosh` to be installed. If you install Swoosh after Identity, then it
    > may be necessary to recompile the entire `:identity` dependency (not just your application).
    > This can be accomplished by running `mix deps.compile identity --force` in each Mix environment.
    > Be aware of this requirement if you use cached build artifacts in CI.

    For more information about notifiers, see `Identity.Notifier`.

    ## Usage

    To use this notifier, configure it in the relevant environment (for example, `config/prod.exs`):

        config :identity,
          # ...
          notifier: Identity.Notifier.Swoosh

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

        config :identity, Identity.Notifier.Swoosh,
          from: "no-reply@my.app",
          mailer: MyApp.Mailer

    | Option | Type | Description |
    | `from` | `string` | Email to use as the "from" address for outgoing emails. **Required**. |
    | `html` | `module` | Module to use while rendering email contents. Must provide `confirm_email_html/1`, `confirm_email_text/1`, `reset_password_html/1`, and `reset_password_text/1` template functions (such as those provided by `Phoenix.Component.embed_templates/2` with the `suffix` option). Defaults to Identity-provided templates. |
    | `layout` | `module` | HTML module with embedded template functions to use while rendering email layouts. The provided module must have `email_html/1` and `email_text/1` functions that accept assigns (such as those provided by `Phoenix.Component.embed_templates/2` with the `suffix` option). Defaults to Identity-provided templates. |
    | `mailer` | `module` | Swoosh Mailer module to use for delivery. The module must `use Swoosh.Mailer`. **Required**. |

    """
    require Phoenix.Component
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
      |> render_body(:confirm_email,
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
      |> render_body(:reset_password,
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
    end

    @spec render_body(Swoosh.Email.t(), atom, keyword) :: Swoosh.Email.t()
    defp render_body(email, template, assigns) do
      layout_module = layout_html()
      template_module = template_html()

      html_heex = apply(template_module, String.to_atom("#{template}_html"), [assigns])

      html =
        if layout_module do
          apply(layout_module, :email_html, [[inner_content: html_heex, title: assigns[:title]]])
        else
          html_heex
        end

      text_heex = apply(template_module, String.to_atom("#{template}_text"), [assigns])

      text =
        if layout_module do
          apply(layout_module, :email_text, [[inner_content: text_heex, title: assigns[:title]]])
        else
          text_heex
        end

      email
      |> Swoosh.Email.html_body(render_heex(html))
      |> Swoosh.Email.text_body(render_heex(text))
    end

    @spec render_heex(term) :: String.t()
    defp render_heex(template) do
      template
      |> Phoenix.HTML.Safe.to_iodata()
      |> IO.iodata_to_binary()
    end

    #
    # Configuration
    #

    @spec from_address :: String.t() | no_return
    defp from_address do
      Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:from] ||
        raise "Identity.Notifier.Swoosh requires a `from` address"
    end

    @spec layout_html :: module | nil
    defp layout_html do
      layout = Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:layout]

      case layout do
        nil ->
          nil

        view when is_atom(view) ->
          view

        _ ->
          Logger.warning("Invalid option `layout` for Identity.Notifier.Swoosh; should be module")
          Identity.Notifier.Swoosh.HTML
      end
    end

    @spec mailer :: module | no_return
    defp mailer do
      Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:mailer] ||
        raise "Identity.Notifier.Swoosh requires a `mailer` module"
    end

    @spec template_html :: module
    defp template_html do
      html = Application.get_env(:identity, Identity.Notifier.Swoosh, [])[:template]

      case html do
        nil ->
          Identity.Notifier.Swoosh.HTML

        html when is_atom(html) ->
          html

        _ ->
          Logger.warning("Invalid option `html` for Identity.Notifier.Swoosh; should be module")
          Identity.Notifier.Swoosh.HTML
      end
    end
  end
end

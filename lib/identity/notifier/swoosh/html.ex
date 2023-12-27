if Code.ensure_loaded?(Swoosh) and Code.ensure_loaded?(Phoenix.Template) do
  defmodule Identity.Notifier.Swoosh.HTML do
    @moduledoc false
    import Phoenix.Template, only: [embed_templates: 2]

    @template_root :code.priv_dir(:identity)
                   |> Path.join("templates/email")

    embed_templates("*.html", root: @template_root, suffix: "_html")
    embed_templates("*.text", root: @template_root, suffix: "_text")
  end
end

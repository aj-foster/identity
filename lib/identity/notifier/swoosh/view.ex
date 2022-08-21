if Code.ensure_loaded?(Swoosh) do
  defmodule Identity.Notifier.Swoosh.View do
    @moduledoc false
    @template_root :code.priv_dir(:identity) |> Path.join("templates/email")
    use Phoenix.View, namespace: Identity.Notifier.Swoosh.View, root: @template_root
  end
end

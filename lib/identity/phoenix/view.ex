if Code.ensure_loaded?(Phoenix.View) do
  defmodule Identity.Phoenix.View do
    @template_root :code.priv_dir(:identity) |> Path.join("templates")
    use Phoenix.View, root: @template_root, namespace: Identity.Phoenix
  end
end

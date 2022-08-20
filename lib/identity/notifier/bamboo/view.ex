if Code.ensure_loaded?(Bamboo.View) do
  defmodule Identity.Notifier.Bamboo.View do
    @moduledoc false
    @template_root :code.priv_dir(:identity) |> Path.join("templates/email")
    use Bamboo.View, path: @template_root
  end
end

defmodule Identity.Phoenix.HTML do
  use Phoenix.Component
  import Identity.Phoenix.Util

  embed_templates "../../../priv/templates/*"

  @doc """
  Generates tag for inlined form input errors.
  """
  def errors(%{field: %Phoenix.HTML.FormField{} = field} = assigns) do
    errors = if Phoenix.Component.used_input?(field), do: field.errors, else: []
    assigns = assign(assigns, :errors, Enum.map(errors, &translate_error/1))

    ~H"""
    <span :for={error <- @errors} class="invalid_feedback" phx-feedback-for={@field.name}>
      {error}
    </span>
    """
  end

  @doc """
  Translates an error message.
  """
  def translate_error({msg, opts}) do
    Enum.reduce(opts, msg, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", fn _ -> to_string(value) end)
    end)
  end
end

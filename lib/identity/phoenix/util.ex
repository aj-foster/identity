defmodule Identity.Phoenix.Util do
  @moduledoc false
  @routes_with_token [:new_password, :create_password, :confirm_email]

  @doc """
  Gets the path for an identity-related controller action, whether the action is implemented by
  Identity or by the consuming application. Raises if the route is not defined.

  This requires the route to be marked `as: :identity` and have the same action name as the
  Identity-implemented action. For example, the session creation route must be defined as:

      post "/any/path", MyAppWeb.AnyController, :create_session, as: :identity

  In the event that multiple routes define the same action with `as: :identity`, the first will
  be used.

  ## Examples

  Because some routes require a path parameter, there are two variations of this function:

      iex> path_for(conn, :new_session)
      "/session/new"

      iex> path_for(conn, :confirm_email, token)
      "/email/:token"

      iex> path_for(conn, :unknown_route)
      ** (RuntimeError) Identity route :unknown_route not found

      iex> path_for(conn, :new_password, token)
      ** (RuntimeError) Identity route :new_password has multiple path parameters: "/password/:token/:other"

  """
  @spec path_for(Plug.Conn.t(), atom, String.t()) :: String.t() | no_return
  def path_for(conn, route, token) when route in @routes_with_token do
    path =
      Phoenix.Controller.router_module(conn)
      |> Phoenix.Router.routes()
      |> Enum.find(fn
        %{helper: "identity", plug_opts: ^route} -> true
        _ -> false
      end)

    if path do
      path.path
      |> Plug.Router.Utils.split()
      |> Enum.reduce({"", false}, fn
        ":" <> _, {_path, true} ->
          raise "Identity route #{inspect(route)} has multiple path parameters: \"#{path.path}\""

        "*" <> _, {_path, true} ->
          raise "Identity route #{inspect(route)} has multiple path parameters: \"#{path.path}\""

        ":" <> _, {path, false} ->
          {"#{path}/#{token}", true}

        "*" <> _, {path, false} ->
          {"#{path}/#{token}", true}

        segment, {path, _} ->
          {"#{path}/#{segment}", false}
      end)
      |> elem(0)
    else
      raise "Identity route #{inspect(route)} not found"
    end
  end

  @doc false
  @spec path_for(Plug.Conn.t(), atom) :: String.t() | no_return
  def path_for(conn, route) do
    path =
      Phoenix.Controller.router_module(conn)
      |> Phoenix.Router.routes()
      |> Enum.find(fn
        %{helper: "identity", plug_opts: ^route} -> true
        _ -> false
      end)

    if path do
      path.path
    else
      raise "Identity route #{inspect(route)} not found"
    end
  end
end

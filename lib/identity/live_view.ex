if Code.ensure_loaded?(Phoenix.LiveView) do
  defmodule Identity.LiveView do
    @moduledoc """
    Provides authentication helpers for LiveView-based applications.
    """

    @doc """
    Callback for `on_mount` calls from live views or live sessions

    This callback can be used from a LiveView directly:

        on_mount {Identity.LiveView, :fetch_identity}

    or when using a live session:

        live_session :example, on_mount: [{Identity.LiveView, :fetch_identity}] do
          live "/example", ExampleLive
        end

    There are three mount actions available:

      * `:fetch_identity` works similarly to the plug of the same name. It uses session
        information (which requires the session to be included in the `connect_info` configuration
        of the live socket) to determine which user is active, and loads that user into an assign
        called `:current_user`. If no user is logged in, then the assign is set to `nil`.

      * `:redirect_if_unauthenticated` works similarly to the plug of the same name. After doing
        the work of `:fetch_identity`, it redirects the client if no user is logged in. The
        destination of the redirect can be controlled using additional options:
        `on_mount {Identity.LiveView, {:redirect_if_unauthenticated, to: "/my/path"}}`. The
        destination defaults to `"/"`.

      * `:redirect_if_authenticated` works similarly to the plug of the same name. After doing the
        work of `:fetch_identity`, it redirects the client if a user is logged in. The destination
        of the redirect can be controlled using additional options:
        `on_mount {Identity.LiveView, {:redirect_if_authenticated, to: "/my/path"}}`. The
        destination defaults to `"/"`.

    ## After-Login Redirection

    When using the `:redirect_if_unauthenticated` callback, it is possible to have the login
    controller redirect the user back to the current route. In order for this callback to have
    access to the current path, however, it is necessary to modify the live socket definition in
    your application's endpoint:

        socket "/live", Phoenix.LiveView.Socket,
          websocket: [connect_info: [:uri, session: @session_options]]

    Specifically, `:uri` must be present in the `connect_info` option.
    """
    @spec on_mount(term, map, map, Phoenix.LiveView.Socket.t()) ::
            {:cont | :halt, Phoenix.LiveView.Socket.t()}
    def on_mount(:fetch_identity, _params, session, socket) do
      {:cont, fetch_identity(socket, session)}
    end

    def on_mount(:redirect_if_unauthenticated, params, session, socket) do
      on_mount({:redirect_if_unauthenticated, []}, params, session, socket)
    end

    def on_mount({:redirect_if_unauthenticated, opts}, _params, session, socket) do
      socket = fetch_identity(socket, session)
      destination = opts[:to] || "/"

      destination =
        if current_uri = Phoenix.LiveView.get_connect_info(socket, :uri) do
          encoded_path =
            Map.merge(current_uri, %{authority: nil, scheme: nil, host: nil, port: nil})
            |> URI.to_string()
            |> String.trim_trailing("?")
            |> URI.encode()

          "#{destination}?after_login=#{encoded_path}"
        else
          destination
        end

      if socket.assigns.current_user do
        {:cont, socket}
      else
        socket =
          socket
          |> Phoenix.LiveView.put_flash(:error, "You must log in to access this page.")
          |> Phoenix.LiveView.redirect(to: destination)

        {:halt, socket}
      end
    end

    def on_mount(:redirect_if_authenticated, params, session, socket) do
      on_mount({:redirect_if_authenticated, []}, params, session, socket)
    end

    def on_mount({:redirect_if_authenticated, opts}, _params, session, socket) do
      socket = fetch_identity(socket, session)

      if socket.assigns.current_user do
        {:halt, Phoenix.LiveView.redirect(socket, to: opts[:to] || "/")}
      else
        {:cont, socket}
      end
    end

    @spec fetch_identity(Phoenix.LiveView.Socket.t(), map) :: Phoenix.LiveView.Socket.t()
    defp fetch_identity(socket, session) do
      Phoenix.Component.assign_new(socket, :current_user, fn ->
        if user_token = session["user_token"] do
          Identity.get_user_by_session(user_token)
        end
      end)
    end
  end
end
